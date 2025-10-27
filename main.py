"""
Secure Ubuntu MCP Server (HTTPS-ready via SSE)

This version preserves your original security & tools, adds:
- config.json (host/port/policy/ssl/servers/transport)
- HTTPS (TLS) via uvicorn
- HTTP/SSE transport with Starlette for Claude Desktop (endpoint: /sse)

"""

import asyncio
import json
import logging
import os
import pwd
import grp
import shutil
import stat
import subprocess
import tempfile
import hashlib
import time
import shlex
from pathlib import Path, PurePath
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re

from mcp.server.fastmcp import FastMCP  # original dependency

# =========================
# Security & Controller (unchanged logic)
# =========================

class SecurityViolation(Exception):
    """Raised when a security policy violation is detected"""
    pass


class PermissionLevel(Enum):
    READ_ONLY = "read_only"
    SAFE_WRITE = "safe_write"
    SYSTEM_ADMIN = "system_admin"
    RESTRICTED = "restricted"


@dataclass
class SecurityPolicy:
    allowed_paths: List[str] = field(default_factory=list)
    forbidden_paths: List[str] = field(default_factory=list)

    allowed_commands: List[str] = field(default_factory=list)
    forbidden_commands: List[str] = field(default_factory=list)
    command_whitelist_mode: bool = True

    max_command_timeout: int = 30
    max_file_size: int = 10 * 1024 * 1024
    max_output_size: int = 1024 * 1024
    max_directory_items: int = 1000

    allow_sudo: bool = False
    resolve_symlinks: bool = True
    check_file_permissions: bool = True
    audit_actions: bool = True
    use_path_cache: bool = False
    use_shell_exec: bool = False

    server_executable_paths: Set[str] = field(default_factory=set)
    system_critical_paths: Set[str] = field(default_factory=set)


class SecurityChecker:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.logger = logging.getLogger(f"{__name__}.security")
        self._path_resolution_cache = {}
        self._cache_max_age = 300
        self._cache_timestamps = {}

    def _get_cache_key(self, path: str) -> str:
        return hashlib.sha256(path.encode()).hexdigest()

    def _is_cache_valid(self, cache_key: str) -> bool:
        if cache_key not in self._cache_timestamps:
            return False
        return time.time() - self._cache_timestamps[cache_key] < self._cache_max_age

    def resolve_path_safely(self, path: str) -> str:
        if self.policy.use_path_cache:
            cache_key = self._get_cache_key(path)
            if self._is_cache_valid(cache_key):
                return self._path_resolution_cache[cache_key]
        try:
            path_obj = Path(os.path.abspath(path))
            if self.policy.resolve_symlinks:
                resolved_path = path_obj.resolve(strict=False)
            else:
                resolved_path = path_obj.absolute()
            canonical_path = str(resolved_path)
            if self.policy.use_path_cache:
                cache_key = self._get_cache_key(path)
                self._path_resolution_cache[cache_key] = canonical_path
                self._cache_timestamps[cache_key] = time.time()
            return canonical_path
        except (OSError, RuntimeError) as e:
            self.logger.warning(f"Path resolution failed for {path}: {e}")
            raise SecurityViolation(f"Cannot resolve path: {path}")

    def validate_path_access(self, path: str, operation: str = "access") -> str:
        canonical_path = self.resolve_path_safely(path)
        for server_path in self.policy.server_executable_paths:
            if canonical_path.startswith(server_path):
                raise SecurityViolation(
                    f"Access denied to server files: {canonical_path}"
                )
        for critical_path in self.policy.system_critical_paths:
            if canonical_path.startswith(critical_path):
                raise SecurityViolation(
                    f"Access denied to critical system path: {canonical_path}"
                )
        for forbidden in self.policy.forbidden_paths:
            forbidden_canonical = self.resolve_path_safely(forbidden)
            if canonical_path.startswith(forbidden_canonical):
                raise SecurityViolation(
                    f"Path explicitly forbidden: {canonical_path}"
                )
        path_allowed = False
        if not self.policy.allowed_paths:
            path_allowed = True
        else:
            for allowed in self.policy.allowed_paths:
                allowed_canonical = self.resolve_path_safely(allowed)
                if canonical_path.startswith(allowed_canonical):
                    path_allowed = True
                    break
        if not path_allowed:
            raise SecurityViolation(
                f"Path not in allowed locations: {canonical_path}"
            )
        if self.policy.check_file_permissions and Path(canonical_path).exists():
            self._check_file_permissions(canonical_path, operation)
        return canonical_path

    def _check_file_permissions(self, path: str, operation: str):
        try:
            path_obj = Path(path)
            stat_info = path_obj.stat()
            current_uid = os.getuid()
            current_gids = [os.getgid()] + os.getgroups()
            file_mode = stat_info.st_mode
            has_perm = False
            if operation in ["read", "access"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IRUSR):
                    has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IRGRP):
                    has_perm = True
                elif file_mode & stat.S_IROTH:
                    has_perm = True
            elif operation in ["write", "modify"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IWUSR):
                    has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IWGRP):
                    has_perm = True
                elif file_mode & stat.S_IWOTH:
                    has_perm = True
            if not has_perm:
                raise SecurityViolation(
                    f"Insufficient permissions for {operation} on {path}"
                )
        except OSError as e:
            raise SecurityViolation(f"Cannot check permissions for {path}: {e}")

    def validate_command(self, command: str) -> List[str]:
        if not command.strip():
            raise SecurityViolation("Empty command not allowed")
        try:
            cmd_parts = shlex.split(command.strip())
        except ValueError as e:
            raise SecurityViolation(f"Invalid command syntax: {e}")
        if not cmd_parts:
            raise SecurityViolation("Empty command after parsing")
        base_command = cmd_parts[0]
        if base_command == 'sudo':
            if not self.policy.allow_sudo:
                raise SecurityViolation("Sudo commands are not allowed by the current security policy.")
            if len(cmd_parts) < 2:
                raise SecurityViolation("Invalid sudo command: missing command to execute.")
            base_command = cmd_parts[1]
        full_command_path = shutil.which(base_command)
        if not full_command_path:
            if os.path.isabs(base_command) and os.path.exists(base_command) and os.access(base_command, os.X_OK):
                full_command_path = base_command
            else:
                raise SecurityViolation(f"Command not found or not executable: {base_command}")
        command_basename = os.path.basename(full_command_path)
        if command_basename in self.policy.forbidden_commands:
            raise SecurityViolation(f"Command explicitly forbidden: {command_basename}")
        if self.policy.command_whitelist_mode:
            if not self.policy.allowed_commands:
                raise SecurityViolation("No commands are allowed (command whitelist is empty).")
            if command_basename not in self.policy.allowed_commands:
                raise SecurityViolation(f"Command not in whitelist: {command_basename}")
        dangerous_patterns = {
            '`': "Backticks (command substitution)",
            '$(': "Dollar-parenthesis (command substitution)",
            ';': "Semicolon (command chaining)",
            '&&': "AND logical operator (command chaining)",
            '||': "OR logical operator (command chaining)",
            '|': "Pipe (command chaining, except for allowed commands)",
        }
        full_command_str = ' '.join(cmd_parts)
        for pattern, desc in dangerous_patterns.items():
            if pattern in full_command_str:
                if pattern == '|' and command_basename in self.policy.allowed_commands:
                    continue
                self.logger.warning(
                    f"Potentially dangerous pattern '{pattern}' detected in command: {full_command_str}")
                if self.policy.use_shell_exec:
                    raise SecurityViolation(f"Dangerous pattern detected in shell command: {desc}")
        return cmd_parts

    def validate_file_operation(self, path: str, operation: str, size: Optional[int] = None) -> str:
        canonical_path = self.validate_path_access(path, operation)
        if size is not None and size > self.policy.max_file_size:
            raise SecurityViolation(
                f"File content size {size} exceeds limit {self.policy.max_file_size}"
            )
        if operation == "read" and Path(canonical_path).exists():
            current_size = Path(canonical_path).stat().st_size
            if current_size > self.policy.max_file_size:
                raise SecurityViolation(
                    f"Existing file is too large to read: {current_size} bytes"
                )
        return canonical_path


class AuditLogger:
    def __init__(self, enabled: bool = True, log_file: str = '/tmp/ubuntu_mcp_audit.log'):
        self.enabled = enabled
        self.logger = logging.getLogger(f"{__name__}.audit")
        if enabled and not self.logger.handlers:
            try:
                audit_handler = logging.FileHandler(log_file)
                audit_formatter = logging.Formatter(
                    '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
                )
                audit_handler.setFormatter(audit_formatter)
                self.logger.addHandler(audit_handler)
                self.logger.setLevel(logging.INFO)
                self.logger.propagate = False
            except (OSError, PermissionError) as e:
                logging.getLogger(__name__).error(f"Failed to configure audit logger at {log_file}: {e}")
                self.enabled = False

    def log_command(self, command: str, user: str, working_dir: Optional[str] = None):
        if self.enabled:
            self.logger.info(f"COMMAND_ATTEMPT: user={user} cmd='{command}' cwd={working_dir or 'default'}")

    def log_file_access(self, operation: str, path: str, user: str, success: bool):
        if self.enabled:
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"FILE_{operation.upper()}: user={user} path='{path}' status={status}")

    def log_security_violation(self, violation: str, user: str, details: str):
        if self.enabled:
            self.logger.warning(f"SECURITY_VIOLATION: user={user} violation='{violation}' details='{details}'")


class SecureUbuntuController:
    def __init__(self, security_policy: SecurityPolicy):
        self.security_policy = security_policy
        self.security_checker = SecurityChecker(security_policy)
        self.audit_logger = AuditLogger(security_policy.audit_actions)
        self.logger = logging.getLogger(__name__)
        try:
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            self.current_user = str(os.getuid())

    async def execute_command(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        self.audit_logger.log_command(command, self.current_user, working_dir)
        try:
            cmd_parts = self.security_checker.validate_command(command)
            resolved_working_dir = None
            if working_dir:
                resolved_working_dir = self.security_checker.validate_path_access(
                    working_dir, "access"
                )
                if not Path(resolved_working_dir).is_dir():
                    raise ValueError(f"Working directory does not exist or is not a directory: {resolved_working_dir}")
            env = os.environ.copy()
            for var in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'IFS']:
                if var in env:
                    del env[var]
            trusted_paths = ['/usr/bin', '/bin', '/usr/local/bin', '/usr/sbin', '/sbin']
            env['PATH'] = ':'.join(trusted_paths)

            if self.security_policy.use_shell_exec:
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=resolved_working_dir,
                    env=env,
                    preexec_fn=os.setpgrp
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=resolved_working_dir,
                    env=env,
                    preexec_fn=os.setpgrp
                )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.security_policy.max_command_timeout
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"Command timed out: {command}")
                try:
                    os.killpg(os.getpgid(process.pid), 9)
                except ProcessLookupError:
                    pass
                raise TimeoutError(f"Command timed out after {self.security_policy.max_command_timeout}s")
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            if len(stdout_str) > self.security_policy.max_output_size:
                stdout_str = stdout_str[:self.security_policy.max_output_size] + "\n\n[...STDOUT TRUNCATED...]"
            if len(stderr_str) > self.security_policy.max_output_size:
                stderr_str = stderr_str[:self.security_policy.max_output_size] + "\n\n[...STDERR TRUNCATED...]"
            return {
                "return_code": process.returncode,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "command": command,
                "executed_as": cmd_parts,
                "working_dir": resolved_working_dir,
                "execution_method": "shell" if self.security_policy.use_shell_exec else "direct"
            }
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("COMMAND_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed for '{command}': {e}", exc_info=True)
            raise

    def list_directory(self, path: str) -> List[Dict[str, Any]]:
        canonical_path = None
        try:
            canonical_path = self.security_checker.validate_path_access(path, "read")
            path_obj = Path(canonical_path)
            if not path_obj.is_dir():
                raise ValueError(f"Path is not a directory: {canonical_path}")
            items = []
            item_count = 0
            for item in path_obj.iterdir():
                if item_count >= self.security_policy.max_directory_items:
                    items.append({
                        "name": f"[TRUNCATED - {self.security_policy.max_directory_items} item limit reached]",
                        "type": "notice",
                        "error": ""
                    })
                    break
                item_count += 1
                try:
                    stat_info = item.stat()
                    owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                    group_name = grp.getgrgid(stat_info.st_gid).gr_name
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat_info.st_size,
                        "permissions": stat.filemode(stat_info.st_mode),
                        "owner": owner_name,
                        "group": group_name,
                        "modified": stat_info.st_mtime,
                        "is_symlink": item.is_symlink()
                    })
                except (OSError, KeyError) as e:
                    items.append({
                        "name": item.name,
                        "type": "unreadable",
                        "error": str(e)
                    })
            self.audit_logger.log_file_access("LIST", canonical_path, self.current_user, True)
            return sorted(items, key=lambda x: (x.get("type", ""), x.get("name", "")))
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("DIRECTORY_LIST_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("LIST", path, self.current_user, False)
            self.logger.error(f"Directory listing failed for '{path}': {e}")
            raise

    def read_file(self, file_path: str) -> str:
        canonical_path = None
        try:
            canonical_path = self.security_checker.validate_file_operation(file_path, "read")
            path_obj = Path(canonical_path)
            if not path_obj.is_file():
                raise ValueError(f"Path is not a regular file: {canonical_path}")
            with open(canonical_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(self.security_policy.max_file_size + 1)
            if len(content) > self.security_policy.max_file_size:
                raise ValueError(f"File is too large to read (>{self.security_policy.max_file_size} bytes)")
            self.audit_logger.log_file_access("READ", canonical_path, self.current_user, True)
            return content
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("FILE_READ_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("READ", file_path, self.current_user, False)
            self.logger.error(f"File read failed for '{file_path}': {e}")
            raise

    def write_file(self, file_path: str, content: str, create_dirs: bool = False) -> bool:
        canonical_path = None
        try:
            content_size = len(content.encode('utf-8'))
            canonical_path = self.security_checker.validate_file_operation(
                file_path, "write", content_size
            )
            path_obj = Path(canonical_path)
            if create_dirs:
                parent_dir = path_obj.parent
                if not parent_dir.exists():
                    self.security_checker.validate_path_access(str(parent_dir), "write")
                    parent_dir.mkdir(parents=True, exist_ok=True)
            if path_obj.exists() and path_obj.is_file():
                backup_path = Path(f"{canonical_path}.backup.{int(time.time())}")
                try:
                    shutil.copy2(canonical_path, backup_path)
                    self.logger.info(f"Created backup: {backup_path}")
                except Exception as e:
                    self.logger.warning(f"Could not create backup for {canonical_path}: {e}")
            temp_fd, temp_path_str = tempfile.mkstemp(
                dir=str(path_obj.parent),
                prefix=f".{path_obj.name}.tmp-"
            )
            temp_path = Path(temp_path_str)
            try:
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    f.write(content)
                shutil.move(str(temp_path), canonical_path)
                self.audit_logger.log_file_access("WRITE", canonical_path, self.current_user, True)
                return True
            finally:
                if temp_path.exists():
                    temp_path.unlink()
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("FILE_WRITE_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("WRITE", file_path, self.current_user, False)
            self.logger.error(f"File write failed for '{file_path}': {e}")
            raise

    def get_system_info(self) -> Dict[str, Any]:
        try:
            info = {}
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = {k: v.strip('"') for k, v in (line.strip().split('=', 1) for line in f if '=' in line)}
                info["os_info"] = os_info
            except Exception:
                info["os_info"] = {"error": "Could not read OS info"}
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_lines = [line for line in f if line.startswith(('MemTotal:', 'MemAvailable:'))]
                    info["memory"] = {k.strip(): v.strip() for k, v in (line.split(':', 1) for line in mem_lines)}
            except Exception:
                info["memory"] = {"error": "Could not read memory info"}
            try:
                disk = shutil.disk_usage('/')
                info["disk_usage_root"] = {"total": disk.total, "used": disk.used, "free": disk.free}
            except Exception:
                info["disk_usage_root"] = {"error": "Could not get disk usage"}
            info.update({
                "current_user": self.current_user,
                "hostname": os.uname().nodename, "platform": os.uname().sysname,
                "architecture": os.uname().machine
            })
            return info
        except Exception as e:
            self.logger.error(f"System info gathering failed: {e}")
            raise


def create_secure_policy() -> SecurityPolicy:
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)
    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp"],
        forbidden_paths=["/etc", "/root", "/boot", "/sys", "/proc", "/dev", "/var/log", "/var/lib", "/usr", "/sbin",
                         "/bin"],
        max_command_timeout=15,
        max_file_size=1 * 1024 * 1024,
        max_output_size=256 * 1024,
        max_directory_items=100,
        allow_sudo=False,
        resolve_symlinks=True,
        check_file_permissions=True,
        audit_actions=True,
        use_path_cache=False,
        use_shell_exec=False,
        command_whitelist_mode=True,
        allowed_commands=[
            "ls", "cat", "echo", "pwd", "whoami", "date", "uname",
            "grep", "head", "tail", "wc", "sort", "uniq", "cut",
            "find", "which", "file", "stat", "du", "df",
            "apt"
        ],
        forbidden_commands=[
            "rm", "rmdir", "dd", "mkfs", "fdisk", "cfdisk", "shutdown",
            "reboot", "halt", "init", "systemctl", "service", "mount", "umount",
            "chmod", "chown", "chgrp", "su", "sudo", "passwd", "useradd",
            "userdel", "usermod", "crontab", "at", "batch", "nohup", "pkill", "kill"
        ],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/etc", "/boot", "/sys", "/proc", "/dev"}
    )


def create_development_policy() -> SecurityPolicy:
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)
    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp", "/opt", "/usr/local"],
        forbidden_paths=["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root", "/boot", "/sys", "/proc"],
        max_command_timeout=60,
        max_file_size=10 * 1024 * 1024,
        max_output_size=1 * 1024 * 1024,
        max_directory_items=500,
        allow_sudo=False,
        resolve_symlinks=True,
        check_file_permissions=True,
        audit_actions=True,
        use_path_cache=False,
        use_shell_exec=False,
        command_whitelist_mode=False,
        allowed_commands=[],
        forbidden_commands=[
            "dd", "mkfs", "fdisk", "cfdisk", "shutdown", "reboot", "halt",
            "init", "passwd", "useradd", "userdel", "usermod", "su", "sudo"
        ],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/boot", "/sys", "/proc", "/dev"}
    )


def create_ubuntu_mcp_server(security_policy: SecurityPolicy) -> FastMCP:
    controller = SecureUbuntuController(security_policy)
    mcp = FastMCP("Secure Ubuntu Controller")

    def format_error(e: Exception) -> str:
        return json.dumps({"error": str(e), "type": type(e).__name__}, indent=2)

    @mcp.tool("execute_command")
    async def execute_command(command: str, working_dir: str = None) -> str:
        try:
            result = await controller.execute_command(command, working_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("list_directory")
    async def list_directory(path: str) -> str:
        try:
            items = controller.list_directory(path)
            return json.dumps(items, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("read_file")
    async def read_file(file_path: str) -> str:
        try:
            return controller.read_file(file_path)
        except Exception as e:
            return format_error(e)

    @mcp.tool("write_file")
    async def write_file(file_path: str, content: str, create_dirs: bool = False) -> str:
        try:
            success = controller.write_file(file_path, content, create_dirs)
            return json.dumps({"success": success, "path": file_path})
        except Exception as e:
            return format_error(e)

    @mcp.tool("get_system_info")
    async def get_system_info() -> str:
        try:
            info = controller.get_system_info()
            return json.dumps(info, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("install_package")
    async def install_package(package_name: str) -> str:
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', package_name):
                raise SecurityViolation(f"Invalid package name format: {package_name}")
            command = f"apt list --installed {shlex.quote(package_name)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("search_packages")
    async def search_packages(query: str) -> str:
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', query):
                raise SecurityViolation(f"Invalid search query format: {query}")
            command = f"apt search {shlex.quote(query)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    return mcp


# =========================
# Optional test runners (kept)
# =========================

async def run_security_tests():
    print("=== Running Security Tests ===")
    policy = create_secure_policy()
    policy.use_shell_exec = False
    controller = SecureUbuntuController(policy)
    results = {}

    async def run_test(name, test_func, *args):
        try:
            await test_func(*args)
            results[name] = "❌ FAIL: Security measure was bypassed."
        except SecurityViolation:
            results[name] = "✅ PASS: Security measure worked as expected."
        except Exception as e:
            results[name] = f"❓ ERROR: Test raised an unexpected exception: {type(e).__name__}: {e}"

    test_symlink = Path("/tmp/symlink_to_etc_passwd")
    if test_symlink.exists(): test_symlink.unlink()
    if not Path("/etc/passwd").exists():
        results["Symlink Attack"] = "❓ SKIP: /etc/passwd not found."
    else:
        os.symlink("/etc/passwd", test_symlink)
        await run_test("Symlink Attack", controller.read_file, str(test_symlink))
        test_symlink.unlink()

    await run_test("Path Traversal", controller.read_file, "/tmp/../../etc/passwd")
    await run_test("Server File Protection", controller.read_file, __file__)
    await run_test("Command Injection (Semicolon)", controller.execute_command, "echo hello; ls /")
    await run_test("Forbidden Command (rm)", controller.execute_command, "rm -rf /")
    await run_test("Non-Whitelisted Command (nmap)", controller.execute_command, "nmap localhost")

    try:
        large_content = "x" * (policy.max_file_size + 1)
        controller.write_file("/tmp/large_file_test.txt", large_content)
        results["File Size Limit"] = "❌ FAIL: Large file write was not blocked."
    except SecurityViolation:
        results["File Size Limit"] = "✅ PASS: Large file write was blocked."
    finally:
        if os.path.exists("/tmp/large_file_test.txt"): os.remove("/tmp/large_file_test.txt")

    print("\n--- Security Test Results ---")
    for name, result in results.items():
        print(f"{name:<25} {result}")

    if any("❌ FAIL" in r for r in results.values()):
        print("\n⚠️  Security vulnerabilities detected!")
        return False
    else:
        print("\n🔒 All security tests passed!")
        return True


async def test_controller():
    print("\n=== Testing Secure Ubuntu Controller Functionality ===")
    policy = create_secure_policy()
    controller = SecureUbuntuController(policy)

    try:
        print("\n1. Testing system info...")
        info = controller.get_system_info()
        print(f"  OS: {info.get('os_info', {}).get('PRETTY_NAME', 'N/A')}, User: {info['current_user']}")

        print("\n2. Testing directory listing...")
        home = os.path.expanduser("~")
        items = controller.list_directory(home)
        print(f"  Found {len(items)} items in {home}. (Truncated at {policy.max_directory_items})")

        print("\n3. Testing safe command execution...")
        res = await controller.execute_command("echo 'Hello from secure controller'")
        print(f"  Command executed. STDOUT: {res['stdout'].strip()}")
        assert res['return_code'] == 0

        print("\n4. Testing file operations...")
        test_file = "/tmp/secure_mcp_test.txt"
        test_content = "This is a test file."
        controller.write_file(test_file, test_content, create_dirs=True)
        print(f"  Wrote to {test_file}")
        read_content = controller.read_file(test_file)
        print(f"  Read back content. Match: {read_content == test_content}")
        assert read_content == test_content
        os.remove(test_file)
        if os.path.exists(f"{test_file}.backup"): os.remove(f"{test_file}.backup")
        print("  Cleaned up test file.")

        print("\n5. Testing expected security violation...")
        try:
            await controller.execute_command("sudo whoami")
        except SecurityViolation as e:
            print(f"  Correctly blocked forbidden command: {e}")

        print("\n✅ All functional tests passed!")

    except Exception as e:
        print(f"❌ A functional test failed: {e}")
        import traceback
        traceback.print_exc()


# =========================
# HTTPS / SSE Server (NEW)
# =========================

def _load_config(path: str = "config.json") -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing {path}. Create it next to main.py.")
    with open(path, "r") as f:
        return json.load(f)

def _build_policy(policy_name: str) -> SecurityPolicy:
    if policy_name == "dev":
        return create_development_policy()
    return create_secure_policy()

def _attach_context_from_config(mcp: FastMCP, cfg: dict):
    # Make servers discoverable by tools
    mcp.context = getattr(mcp, "context", {})
    mcp.context["servers"] = cfg.get("servers", [])

def _build_starlette_sse_app(mcp: FastMCP):
    """
    Build a Starlette app that exposes SSE endpoints for MCP:
      - GET /sse           (SSE stream)
      - POST /messages/    (post messages)
    Pattern based on public examples using SseServerTransport.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount
    from mcp.server.sse import SseServerTransport

    transport = SseServerTransport("/messages/")

    async def handle_sse(request):
        # Establish SSE connection and delegate to MCP server
        async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
            read_stream, write_stream = streams
            await mcp._mcp_server.run(  # uses FastMCP's underlying server
                read_stream,
                write_stream,
                mcp._mcp_server.create_initialization_options()
            )

    routes = [
        Route("/sse", endpoint=handle_sse),                # Claude connects here (GET)
        Mount("/messages/", app=transport.handle_post_message),  # Client POSTs messages here
    ]
    return Starlette(routes=routes)

async def _run_stdio(mcp: FastMCP):
    # Preserve original behavior (local stdio)
    await mcp.run_stdio_async()

def _get_ssl_params(ssl_cfg: dict) -> dict:
    if not ssl_cfg.get("enabled"):
        return {}
    certfile = ssl_cfg.get("certfile")
    keyfile = ssl_cfg.get("keyfile")
    if not certfile or not keyfile:
        raise ValueError("SSL enabled but 'certfile' or 'keyfile' missing in config.json")
    if not os.path.exists(certfile):
        raise FileNotFoundError(f"SSL cert not found: {certfile}")
    if not os.path.exists(keyfile):
        raise FileNotFoundError(f"SSL key not found: {keyfile}")
    return {"ssl_certfile": certfile, "ssl_keyfile": keyfile}


def _print_boot(cfg: dict, using_https: bool):
    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 8585)
    scheme = "https" if using_https else "http"
    print(f"🚀 Secure Ubuntu MCP Server listening at {scheme}://{host}:{port}")
    if using_https:
        print("🔒 TLS is enabled")
    print("📡 SSE endpoint: /sse (use this URL in Claude Desktop)")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secure Ubuntu MCP Server (HTTPS-ready via SSE)")
    parser.add_argument("--security-test", action="store_true", help="Run security validation tests and exit")
    parser.add_argument("--test", action="store_true", help="Run functionality tests and exit")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if args.security_test:
        ok = await run_security_tests()
        raise SystemExit(0 if ok else 1)

    if args.test:
        await test_controller()
        return

    cfg = _load_config(args.config)
    policy = _build_policy(cfg.get("policy", "secure"))
    mcp_server = create_ubuntu_mcp_server(policy)
    _attach_context_from_config(mcp_server, cfg)

    transport = cfg.get("transport", "http").lower()
    if transport == "stdio":
        print("ℹ️ Transport = stdio (local). To use HTTPS+SSE, set \"transport\": \"http\" in config.json")
        await _run_stdio(mcp_server)
        return

    # HTTP/SSE + HTTPS (for Claude)
    app = _build_starlette_sse_app(mcp_server)
    host = cfg.get("host", "0.0.0.0")
    port = int(cfg.get("port", 8585))
    ssl_params = _get_ssl_params(cfg.get("ssl", {}))
    _print_boot(cfg, using_https=bool(ssl_params))

    import uvicorn
    config = uvicorn.Config(app=app, host=host, port=port, **ssl_params)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    import sys
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Secure Ubuntu MCP Server stopped by user.", file=sys.stderr)
    except Exception as e:
        logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
        sys.exit(1)
