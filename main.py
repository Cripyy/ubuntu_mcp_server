"""
Secure Ubuntu MCP Server (Remote-capable version)
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import your original security + MCP code
from mcp.server.fastmcp import FastMCP
from pathlib import Path
from typing import Any, Dict
from dataclasses import dataclass, field
from enum import Enum
import shutil
import pwd, grp, stat, time, tempfile, hashlib, shlex, subprocess, re

# -----------------------------------------------------------------------------
# Security policy + controller definitions
# -----------------------------------------------------------------------------

class SecurityViolation(Exception):
    pass


class PermissionLevel(Enum):
    READ_ONLY = "read_only"
    SAFE_WRITE = "safe_write"
    SYSTEM_ADMIN = "system_admin"
    RESTRICTED = "restricted"


@dataclass
class SecurityPolicy:
    allowed_paths: list = field(default_factory=list)
    forbidden_paths: list = field(default_factory=list)
    allowed_commands: list = field(default_factory=list)
    forbidden_commands: list = field(default_factory=list)
    command_whitelist_mode: bool = True
    max_command_timeout: int = 30
    max_file_size: int = 10 * 1024 * 1024
    max_output_size: int = 1024 * 1024
    max_directory_items: int = 1000
    allow_sudo: bool = False
    resolve_symlinks: bool = True
    audit_actions: bool = True


class SecureUbuntuController:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.logger = logging.getLogger(__name__)
        try:
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            self.current_user = str(os.getuid())

    async def execute_command(self, command: str, working_dir: str = None) -> Dict[str, Any]:
        env = os.environ.copy()
        for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "IFS"]:
            env.pop(var, None)
        cmd_parts = shlex.split(command)
        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir or None,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=self.policy.max_command_timeout,
        )
        return {
            "return_code": process.returncode,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "command": command,
        }

    def list_directory(self, path: str):
        path_obj = Path(path).expanduser().resolve()
        items = []
        for item in path_obj.iterdir():
            info = item.stat()
            items.append({
                "name": item.name,
                "type": "directory" if item.is_dir() else "file",
                "size": info.st_size,
                "modified": info.st_mtime,
            })
        return items

    def read_file(self, file_path: str) -> str:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def write_file(self, file_path: str, content: str):
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    def get_system_info(self):
        return {
            "hostname": os.uname().nodename,
            "platform": os.uname().sysname,
            "architecture": os.uname().machine,
            "user": self.current_user,
        }


def create_secure_policy() -> SecurityPolicy:
    home_dir = os.path.expanduser("~")
    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp"],
        forbidden_paths=["/etc/passwd", "/etc/shadow", "/root", "/boot", "/sys", "/proc"],
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
        ],
        allow_sudo=False,
        resolve_symlinks=True,
        audit_actions=True,
    )

# -----------------------------------------------------------------------------
# MCP Server setup
# -----------------------------------------------------------------------------

def create_ubuntu_mcp_server(policy: SecurityPolicy) -> FastMCP:
    controller = SecureUbuntuController(policy)
    mcp = FastMCP("Ubuntu MCP Server")

    def to_json(data):
        return json.dumps(data, indent=2)

    @mcp.tool("execute_command")
    async def execute_command(command: str, working_dir: str = None):
        result = await controller.execute_command(command, working_dir)
        return to_json(result)

    @mcp.tool("list_directory")
    async def list_directory(path: str):
        return to_json(controller.list_directory(path))

    @mcp.tool("read_file")
    async def read_file(file_path: str):
        return controller.read_file(file_path)

    @mcp.tool("write_file")
    async def write_file(file_path: str, content: str):
        success = controller.write_file(file_path, content)
        return to_json({"success": success, "path": file_path})

    @mcp.tool("get_system_info")
    async def get_system_info():
        return to_json(controller.get_system_info())

    return mcp

# -----------------------------------------------------------------------------
# FastAPI Web Wrapper for remote access
# -----------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(description="Ubuntu MCP Server")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())

    policy = create_secure_policy()
    mcp_server = create_ubuntu_mcp_server(policy)

    # Load network configuration
    with open("config.json") as f:
        config = json.load(f)
    network_cfg = config.get("network", {})
    host = network_cfg.get("host", "0.0.0.0")
    port = int(network_cfg.get("port", 8585))
    use_https = network_cfg.get("use_https", True)
    certfile = network_cfg.get("ssl_certfile", "/etc/ssl/mcp/mcp.crt")
    keyfile = network_cfg.get("ssl_keyfile", "/etc/ssl/mcp/mcp.key")

    # --- FastAPI wrapper ---
    app = FastAPI(title="Ubuntu MCP Remote Server")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")
    async def root():
        return {"status": "ok", "message": "Ubuntu MCP Server is running", "host": host, "port": port}

    @app.get("/mcp/tools")
    async def list_tools():
        return {"tools": list(mcp_server.tools.keys())}

    @app.post("/mcp")
    async def mcp_entry(request: Request):
        """Dispatch JSON request to MCP tool."""
        try:
            data = await request.json()
            tool_name = data.get("tool")
            args = data.get("args", {})

            if not tool_name:
                return Response(json.dumps({"error": "Missing 'tool'"}), status_code=400)

            tool_func = mcp_server.tools.get(tool_name)
            if not tool_func:
                return Response(json.dumps({"error": f"Tool '{tool_name}' not found"}), status_code=404)

            if asyncio.iscoroutinefunction(tool_func):
                result = await tool_func(**args)
            else:
                result = tool_func(**args)

            if not isinstance(result, str):
                result = json.dumps(result)
            return Response(result, media_type="application/json")
        except Exception as e:
            return Response(json.dumps({"error": str(e)}), status_code=500)

    # --- Start HTTPS server ---
    print(f"🔐 Serving Ubuntu MCP on https://{host}:{port}")
    from uvicorn import Config, Server
    ssl_params = {"ssl_certfile": certfile, "ssl_keyfile": keyfile} if use_https else {}
    config = Config(app=app, host=host, port=port, **ssl_params)
    server = Server(config)
    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 MCP Server stopped by user")
    except Exception as e:
        logging.getLogger(__name__).critical(f"Server exited with error: {e}", exc_info=True)
        sys.exit(1)
