#!/usr/bin/env python3
"""
Ubuntu MCP Server

A Model Context Protocol server for controlling Ubuntu systems.
Provides safe, controlled access to system operations.
"""

import asyncio
import json
import logging
import os
import pwd
import grp
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# MCP Protocol implementation
from mcp.server.fastmcp import FastMCP


class PermissionLevel(Enum):
    """Define permission levels for operations"""
    READ_ONLY = "read_only"
    SAFE_WRITE = "safe_write"
    SYSTEM_ADMIN = "system_admin"
    RESTRICTED = "restricted"


@dataclass
class SecurityPolicy:
    """Security policy configuration"""
    allowed_paths: List[str]
    forbidden_paths: List[str]
    allowed_commands: List[str]
    forbidden_commands: List[str]
    max_command_timeout: int = 30
    allow_sudo: bool = False


class UbuntuController:
    """Core Ubuntu system controller with security controls"""
    
    def __init__(self, security_policy: SecurityPolicy):
        self.security_policy = security_policy
        self.logger = logging.getLogger(__name__)
        
    def _is_path_allowed(self, path: str) -> bool:
        """Check if path is within allowed directories"""
        abs_path = os.path.abspath(path)
        
        # Check forbidden paths first
        for forbidden in self.security_policy.forbidden_paths:
            if abs_path.startswith(os.path.abspath(forbidden)):
                return False
                
        # Check allowed paths
        for allowed in self.security_policy.allowed_paths:
            if abs_path.startswith(os.path.abspath(allowed)):
                return True
                
        return False
    
    def _is_command_allowed(self, command: str) -> bool:
        """Check if command is allowed to execute"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return False
            
        base_command = cmd_parts[0]
        
        # Check forbidden commands
        if base_command in self.security_policy.forbidden_commands:
            return False
            
        # If allowed commands list exists, check it
        if self.security_policy.allowed_commands:
            return base_command in self.security_policy.allowed_commands
            
        return True
    
    async def execute_command(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute a shell command with security controls"""
        if not self._is_command_allowed(command):
            raise PermissionError(f"Command not allowed: {command}")
            
        if working_dir and not self._is_path_allowed(working_dir):
            raise PermissionError(f"Working directory not allowed: {working_dir}")
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.security_policy.max_command_timeout
            )
            
            return {
                "return_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "command": command
            }
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"Command timed out: {command}")
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise
    
    def list_directory(self, path: str) -> List[Dict[str, Any]]:
        """List directory contents with metadata"""
        if not self._is_path_allowed(path):
            raise PermissionError(f"Path not allowed: {path}")
            
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")
                
            items = []
            for item in path_obj.iterdir():
                stat_info = item.stat()
                items.append({
                    "name": item.name,
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file",
                    "size": stat_info.st_size,
                    "permissions": oct(stat_info.st_mode)[-3:],
                    "owner": pwd.getpwuid(stat_info.st_uid).pw_name,
                    "group": grp.getgrgid(stat_info.st_gid).gr_name,
                    "modified": stat_info.st_mtime
                })
            
            return sorted(items, key=lambda x: (x["type"], x["name"]))
            
        except Exception as e:
            self.logger.error(f"Directory listing failed: {e}")
            raise
    
    def read_file(self, file_path: str, max_size: int = 1024*1024) -> str:
        """Read file contents with size limits"""
        if not self._is_path_allowed(file_path):
            raise PermissionError(f"File path not allowed: {file_path}")
            
        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                raise FileNotFoundError(f"File does not exist: {file_path}")
                
            if path_obj.stat().st_size > max_size:
                raise ValueError(f"File too large (>{max_size} bytes): {file_path}")
                
            with open(path_obj, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
                
        except Exception as e:
            self.logger.error(f"File read failed: {e}")
            raise
    
    def write_file(self, file_path: str, content: str, create_dirs: bool = False) -> bool:
        """Write content to file with safety checks"""
        if not self._is_path_allowed(file_path):
            raise PermissionError(f"File path not allowed: {file_path}")
            
        try:
            path_obj = Path(file_path)
            
            if create_dirs:
                path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Create backup if file exists
            if path_obj.exists():
                backup_path = f"{file_path}.backup"
                shutil.copy2(path_obj, backup_path)
            
            with open(path_obj, 'w', encoding='utf-8') as f:
                f.write(content)
                
            return True
            
        except Exception as e:
            self.logger.error(f"File write failed: {e}")
            raise
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        try:
            # Get OS information
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
            
            # Get system resources
            with open('/proc/meminfo', 'r') as f:
                memory_info = {}
                for line in f:
                    if line.startswith(('MemTotal:', 'MemAvailable:', 'MemFree:')):
                        key, value = line.split(':', 1)
                        memory_info[key.strip()] = value.strip()
            
            # Get disk usage
            disk_usage = shutil.disk_usage('/')
            
            return {
                "os_info": os_info,
                "memory": memory_info,
                "disk_usage": {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free
                },
                "current_user": os.getenv('USER', 'unknown'),
                "hostname": os.uname().nodename
            }
            
        except Exception as e:
            self.logger.error(f"System info gathering failed: {e}")
            raise


def create_safe_policy() -> SecurityPolicy:
    """Create a conservative security policy"""
    home_dir = os.path.expanduser("~")
    
    return SecurityPolicy(
        allowed_paths=[
            home_dir,
            "/tmp",
            "/var/tmp",
            "/opt",
            "/usr/local"
        ],
        forbidden_paths=[
            "/etc/passwd",
            "/etc/shadow",
            "/root",
            "/boot",
            "/sys",
            "/proc"
        ],
        max_command_timeout=30,
        allow_sudo=False,
        allowed_commands=[
            "ls", "cat", "echo", "pwd", "whoami", "date", "uname",
            "grep", "find", "which", "file", "head", "tail",
            "apt", "dpkg", "snap", "git", "curl", "wget",
            "python3", "pip3", "npm", "node", "docker"
        ],
        forbidden_commands=[
            "rm", "rmdir", "dd", "mkfs", "fdisk", "cfdisk",
            "shutdown", "reboot", "halt", "init", "systemctl",
            "service", "mount", "umount", "chmod", "chown"
        ]
    )


def create_development_policy() -> SecurityPolicy:
    """Create a more permissive policy for development"""
    home_dir = os.path.expanduser("~")
    
    return SecurityPolicy(
        allowed_paths=[
            home_dir,
            "/tmp",
            "/var/tmp",
            "/opt",
            "/usr/local",
            "/var/log"
        ],
        forbidden_paths=[
            "/etc/passwd",
            "/etc/shadow",
            "/root",
            "/boot"
        ],
        max_command_timeout=60,
        allow_sudo=True,
        allowed_commands=[],  # Empty list means all commands allowed except forbidden
        forbidden_commands=[
            "dd", "mkfs", "fdisk", "cfdisk",
            "shutdown", "reboot", "halt", "init"
        ]
    )


def create_ubuntu_mcp_server(security_policy: SecurityPolicy) -> FastMCP:
    """Create and configure the Ubuntu MCP server"""
    
    # Initialize the controller
    controller = UbuntuController(security_policy)
    
    # Create FastMCP server
    mcp = FastMCP("Ubuntu Controller")
    
    @mcp.tool("execute_command")
    async def execute_command(command: str, working_dir: str = None) -> str:
        """Execute a shell command on the Ubuntu system
        
        Args:
            command: The shell command to execute
            working_dir: Optional working directory for the command
            
        Returns:
            JSON string with command results
        """
        try:
            result = await controller.execute_command(command, working_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    @mcp.tool("list_directory")
    async def list_directory(path: str) -> str:
        """List contents of a directory
        
        Args:
            path: Directory path to list
            
        Returns:
            JSON string with directory contents
        """
        try:
            items = controller.list_directory(path)
            return json.dumps(items, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    @mcp.tool("read_file")
    async def read_file(file_path: str) -> str:
        """Read contents of a file
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            File contents as string
        """
        try:
            content = controller.read_file(file_path)
            return content
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    @mcp.tool("write_file")
    async def write_file(file_path: str, content: str, create_dirs: bool = False) -> str:
        """Write content to a file
        
        Args:
            file_path: Path where to write the file
            content: Content to write
            create_dirs: Whether to create parent directories if they don't exist
            
        Returns:
            Success or error message
        """
        try:
            success = controller.write_file(file_path, content, create_dirs)
            return f"File written successfully: {file_path}" if success else "Write failed"
        except Exception as e:
            return f"Error writing file: {str(e)}"
    
    @mcp.tool("get_system_info")
    async def get_system_info() -> str:
        """Get system information
        
        Returns:
            JSON string with system information
        """
        try:
            info = controller.get_system_info()
            return json.dumps(info, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    @mcp.tool("install_package")
    async def install_package(package_name: str, use_sudo: bool = False) -> str:
        """Install a package using apt
        
        Args:
            package_name: Name of the package to install
            use_sudo: Whether to use sudo (requires permission in security policy)
            
        Returns:
            JSON string with installation results
        """
        if not controller.security_policy.allow_sudo and use_sudo:
            return json.dumps({"error": "Sudo operations not allowed"}, indent=2)
            
        try:
            cmd = f"{'sudo ' if use_sudo else ''}apt install -y {package_name}"
            result = await controller.execute_command(cmd)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    @mcp.tool("search_packages")
    async def search_packages(query: str) -> str:
        """Search for packages using apt
        
        Args:
            query: Search query for packages
            
        Returns:
            Search results as string
        """
        try:
            result = await controller.execute_command(f"apt search {query}")
            return result["stdout"]
        except Exception as e:
            return f"Error searching packages: {str(e)}"
    
    return mcp


async def test_controller():
    """Test the Ubuntu controller functionality standalone"""
    print("=== Testing Ubuntu Controller ===")
    
    # Create a safe policy for testing
    policy = create_safe_policy()
    controller = UbuntuController(policy)
    
    try:
        print("\n1. Testing system info...")
        system_info = controller.get_system_info()
        print(f"OS: {system_info['os_info'].get('PRETTY_NAME', 'Unknown')}")
        print(f"User: {system_info['current_user']}")
        print(f"Hostname: {system_info['hostname']}")
        
        print("\n2. Testing directory listing...")
        home_dir = os.path.expanduser("~")
        items = controller.list_directory(home_dir)
        print(f"Found {len(items)} items in {home_dir}")
        for item in items[:3]:  # Show first 3 items
            print(f"  {item['type']:10} {item['name']:20} {item['size']:10} bytes")
        
        print("\n3. Testing command execution...")
        result = await controller.execute_command("echo 'Hello from Ubuntu MCP Server!'")
        print(f"Command output: {result['stdout'].strip()}")
        print(f"Return code: {result['return_code']}")
        
        print("\n4. Testing file operations...")
        test_file = "/tmp/mcp_test.txt"
        test_content = "This is a test file created by Ubuntu MCP Server"
        
        # Write test file
        controller.write_file(test_file, test_content)
        print(f"Written test file: {test_file}")
        
        # Read test file
        read_content = controller.read_file(test_file)
        print(f"Read content: {read_content}")
        
        # Clean up
        os.remove(test_file)
        print("Test file cleaned up")
        
        print("\n✅ All tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")


async def main():
    """Main entry point"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Ubuntu MCP Server")
    parser.add_argument("--policy", choices=["safe", "dev"], default="safe",
                       help="Security policy to use")
    parser.add_argument("--test", action="store_true",
                       help="Run tests instead of starting server")
    parser.add_argument("--log-level", default="INFO",
                       help="Logging level")
    
    args = parser.parse_args()
    
    # Setup logging to stderr (MCP standard)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stderr
    )
    
    if args.test:
        await test_controller()
        return
    
    # Create security policy
    if args.policy == "dev":
        policy = create_development_policy()
    else:
        policy = create_safe_policy()
    
    print(f"Starting Ubuntu MCP Server with {args.policy} policy...", file=sys.stderr)
    print(f"Allowed paths: {policy.allowed_paths}", file=sys.stderr)
    print(f"Allowed commands: {policy.allowed_commands[:5]}...", file=sys.stderr)
    
    # Create and run server
    mcp = create_ubuntu_mcp_server(policy)
    
    # Run the server directly with stdio (avoids nested event loops)
    await mcp.run_stdio_async()


if __name__ == "__main__":
    import sys
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Ubuntu MCP Server stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"❌ Server error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)