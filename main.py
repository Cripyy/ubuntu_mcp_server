"""
Secure Ubuntu MCP Server — Streamable HTTP (remote-ready)
- HTTPS on :8585
- MCP Streamable HTTP mounted at /mcp
- Health + debug routes for quick checks
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import shlex
import pwd, grp, stat, tempfile, shutil, time

import uvicorn
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Core MCP server (Python SDK)
from mcp.server.fastmcp import FastMCP

# ────────────────────────────────────────────────────────────────────────────────
# Security / Policy
# ────────────────────────────────────────────────────────────────────────────────

class SecurityViolation(Exception):
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
    allow_sudo: bool = False

# ────────────────────────────────────────────────────────────────────────────────
# Controller with safe-ish helpers (kept pragmatic to get you running)
# ────────────────────────────────────────────────────────────────────────────────

class SecureUbuntuController:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.logger = logging.getLogger(__name__)
        try:
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            self.current_user = str(os.getuid())

    async def execute_command(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        # Minimal command guardrail (you can expand as needed)
        if not command or not isinstance(command, str):
            raise SecurityViolation("Empty command")

        parts = shlex.split(command)
        base = parts[0]

        if base in self.policy.forbidden_commands:
            raise SecurityViolation(f"Command forbidden: {base}")

        if self.policy.command_whitelist_mode and base not in self.policy.allowed_commands:
            raise SecurityViolation(f"Command not allowed by whitelist: {base}")

        if base == "sudo" and not self.policy.allow_sudo:
            raise SecurityViolation("sudo is disabled by policy")

        # Clean environment
        env = os.environ.copy()
        for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "IFS"]:
            env.pop(var, None)

        proc = await asyncio.create_subprocess_exec(
            *parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir or None,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.policy.max_command_timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise TimeoutError(f"Command timed out after {self.policy.max_command_timeout}s")

        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        if len(out) > self.policy.max_output_size:
            out = out[: self.policy.max_output_size] + "\n[...STDOUT TRUNCATED...]"
        if len(err) > self.policy.max_output_size:
            err = err[: self.policy.max_output_size] + "\n[...STDERR TRUNCATED...]"

        return {
            "return_code": proc.returncode,
            "stdout": out,
            "stderr": err,
            "command": command,
            "cwd": working_dir or os.getcwd(),
        }

    def list_directory(self, path: str) -> List[Dict[str, Any]]:
        p = Path(path).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            raise FileNotFoundError(f"Not a directory: {p}")

        items: List[Dict[str, Any]] = []
        for item in p.iterdir():
            try:
                st = item.stat()
                items.append({
                    "name": item.name,
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file",
                    "size": st.st_size,
                    "modified": st.st_mtime,
                })
            except OSError as e:
                items.append({
                    "name": item.name,
                    "path": str(item),
                    "type": "unreadable",
                    "error": str(e),
                })
        return items

    def read_file(self, file_path: str) -> str:
        p = Path(file_path).expanduser().resolve()
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(str(p))
        if p.stat().st_size > self.policy.max_file_size:
            raise SecurityViolation("File too large")
        return p.read_text(encoding="utf-8", errors="replace")

    def write_file(self, file_path: str, content: str) -> bool:
        p = Path(file_path).expanduser().resolve()
        data = content.encode("utf-8")
        if len(data) > self.policy.max_file_size:
            raise SecurityViolation("Write exceeds max file size")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(f"{p}.tmp-{int(time.time())}")
        tmp.write_bytes(data)
        tmp.replace(p)
        return True

    def get_system_info(self) -> Dict[str, Any]:
        return {
            "hostname": os.uname().nodename,
            "platform": os.uname().sysname,
            "architecture": os.uname().machine,
            "user": self.current_user,
        }

# ────────────────────────────────────────────────────────────────────────────────
# Policies
# ────────────────────────────────────────────────────────────────────────────────

def create_secure_policy() -> SecurityPolicy:
    home = os.path.expanduser("~")
    return SecurityPolicy(
        allowed_paths=[home, "/tmp", "/var/tmp"],
        forbidden_paths=["/etc/shadow", "/root", "/boot", "/sys", "/proc"],
        allowed_commands=[
            "ls","cat","echo","pwd","whoami","date","uname",
            "grep","find","which","file","head","tail",
            "apt","dpkg","snap","git","curl","wget",
            "python3","pip3","npm","node","docker"
        ],
        forbidden_commands=[
            "rm","rmdir","dd","mkfs","fdisk","cfdisk",
            "shutdown","reboot","halt","init","systemctl",
            "service","mount","umount","chmod","chown"
        ],
        allow_sudo=False,
        command_whitelist_mode=True,
        max_command_timeout=30,
        max_file_size=10 * 1024 * 1024,
        max_output_size=1 * 1024 * 1024,
    )

def create_development_policy() -> SecurityPolicy:
    home = os.path.expanduser("~")
    return SecurityPolicy(
        allowed_paths=[home, "/tmp", "/var/tmp", "/opt", "/usr/local"],
        forbidden_paths=["/etc/shadow","/root"],
        allowed_commands=[],               # not used when whitelist_mode=False
        forbidden_commands=["rm","shutdown","reboot"],
        allow_sudo=False,
        command_whitelist_mode=False,
        max_command_timeout=60,
        max_file_size=10 * 1024 * 1024,
        max_output_size=1 * 1024 * 1024,
    )

# ────────────────────────────────────────────────────────────────────────────────
# Build MCP server with your tools
# ────────────────────────────────────────────────────────────────────────────────

def build_mcp(
    policy: SecurityPolicy,
    *,
    log_level: str,
    host: str,
    port: int,
    policy_name: str,
) -> FastMCP:
    ctrl = SecureUbuntuController(policy)
    mcp = FastMCP(
        "Ubuntu MCP Server",
        log_level=log_level,
        host=host,
        port=port,
        streamable_http_path="/mcp",
    )

    # Keep a registry so we can show tools at /debug/tools
    mcp._tool_names: List[str] = []

    def register(name):
        def deco(fn):
            mcp.tool(name)(fn)
            mcp._tool_names.append(name)
            return fn

        return deco

    @register("execute_command")
    async def _execute_command(command: str, working_dir: Optional[str] = None) -> str:
        return json.dumps(await ctrl.execute_command(command, working_dir), indent=2)

    @register("list_directory")
    def _list_directory(path: str) -> str:
        return json.dumps(ctrl.list_directory(path), indent=2)

    @register("read_file")
    def _read_file(file_path: str) -> str:
        return ctrl.read_file(file_path)

    @register("write_file")
    def _write_file(file_path: str, content: str) -> str:
        ok = ctrl.write_file(file_path, content)
        return json.dumps({"success": ok, "path": file_path})

    @register("get_system_info")
    def _get_system_info() -> str:
        return json.dumps(ctrl.get_system_info(), indent=2)

    @mcp.custom_route("/", methods=["GET"])
    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "message": "Ubuntu MCP Server running", "policy": policy_name})

    @mcp.custom_route("/debug/tools", methods=["GET"])
    async def debug_tools(_: Request) -> JSONResponse:
        return JSONResponse({"tools": getattr(mcp, "_tool_names", [])})

    return mcp

# ────────────────────────────────────────────────────────────────────────────────
# App entry — mount Streamable HTTP at /mcp (Claude-friendly)
# ────────────────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Secure Ubuntu MCP Server")
    parser.add_argument("--policy", choices=["secure","dev"], default="secure")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())

    policy = create_development_policy() if args.policy == "dev" else create_secure_policy()

    # Read network config (optional)
    host = "0.0.0.0"
    port = 8585
    use_https = True
    certfile = "/etc/ssl/mcp/mcp.crt"
    keyfile  = "/etc/ssl/mcp/mcp.key"
    cfg_file = Path("config.json")
    if cfg_file.exists():
        try:
            cfg = json.loads(cfg_file.read_text())
            net = cfg.get("network", {})
            host      = net.get("host", host)
            port      = int(net.get("port", port))
            use_https = net.get("use_https", use_https)
            certfile  = net.get("ssl_certfile", certfile)
            keyfile   = net.get("ssl_keyfile", keyfile)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to parse config.json: {e}")

    mcp = build_mcp(
        policy,
        log_level=args.log_level.upper(),
        host=host,
        port=port,
        policy_name=args.policy,
    )

    app = mcp.streamable_http_app()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id"],
    )

    # Start HTTPS server (optional)
    ssl_kwargs = {"ssl_certfile": certfile, "ssl_keyfile": keyfile} if use_https else {}
    scheme = "https" if use_https else "http"
    print(f"🔐 Serving MCP ({args.policy}) on {scheme}://{host}:{port}/mcp")
    print(f"   Health: {scheme}://{host}:{port}/")
    config = uvicorn.Config(app=app, host=host, port=port, log_level=args.log_level.lower(), **ssl_kwargs)
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
    except Exception as e:
        logging.getLogger(__name__).critical(f"Fatal: {e}", exc_info=True)
        sys.exit(1)