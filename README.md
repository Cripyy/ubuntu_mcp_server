# Ubuntu MCP Server

A Model Context Protocol (MCP) server that provides secure, controlled access to Ubuntu system operations. This server allows AI assistants to interact with Ubuntu systems through a well-defined protocol with configurable security policies.

## Features

### 🔒 Security-First Design
- **Path-based access control**: Only allows operations in explicitly permitted directories
- **Command filtering**: Whitelist/blacklist approach for shell commands
- **Configurable security policies**: Safe mode vs development mode
- **Timeout protection**: Prevents runaway processes
- **No sudo by default**: Can be enabled with explicit configuration

### 🛠 Core Capabilities
- **File Operations**: Read, write, list directories with permission checks
- **Command Execution**: Run shell commands with security controls
- **Package Management**: Search and install packages via apt
- **System Information**: Get OS details, memory, disk usage
- **Process Management**: With appropriate security policies

### 🏗 Architecture
- **Modular Design**: Clear separation between security, controller, and MCP layers
- **Production Ready**: Includes logging, error handling, and comprehensive testing
- **Extensible**: Easy to add new tools and capabilities

## Installation

1. **Clone and setup**:
```bash
git clone <repository>
cd ubuntu_mcp_server
```

2. **Create virtual environment**:
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## Usage

### Testing the Controller

Run the built-in tests to verify everything works:

```bash
python main.py --test
```

You should see output like:
```
=== Testing Ubuntu Controller ===

1. Testing system info...
OS: Ubuntu 24.04.2 LTS
User: your_username
Hostname: your_hostname

2. Testing directory listing...
Found X items in /home/your_username
...

✅ All tests passed!
```

### Running as MCP Server

Start the server with default (safe) security policy:

```bash
python main.py
```

Or with development policy (more permissive):

```bash
python main.py --policy dev
```

### Testing with MCP Client

Run the test client to verify MCP protocol functionality:

```bash
python test_client.py --simple
```

## Security Policies

### Safe Policy (Default)
- **Allowed paths**: `~/`, `/tmp`, `/var/tmp`, `/opt`, `/usr/local`
- **Forbidden paths**: `/etc/passwd`, `/etc/shadow`, `/root`, `/boot`, `/sys`, `/proc`
- **Allowed commands**: Basic commands like `ls`, `cat`, `echo`, `apt`, `git`, `python3`
- **Forbidden commands**: Destructive commands like `rm`, `dd`, `shutdown`, `mount`
- **Sudo**: Disabled

### Development Policy
- **Allowed paths**: Includes `/var/log` in addition to safe policy paths
- **Fewer forbidden paths**: Only critical system areas protected
- **More commands allowed**: Nearly all commands except destructive ones
- **Sudo**: Enabled (use with caution)

## Available MCP Tools

### File Operations
- `list_directory(path)` - List directory contents with metadata
- `read_file(file_path)` - Read file contents with size limits
- `write_file(file_path, content, create_dirs=False)` - Write content to file

### System Operations
- `execute_command(command, working_dir=None)` - Execute shell commands
- `get_system_info()` - Get OS, memory, and disk information

### Package Management
- `search_packages(query)` - Search for packages using apt
- `install_package(package_name, use_sudo=False)` - Install packages via apt

## Configuration

### Using config.json

The server can be configured using a `config.json` file:

```json
{
  "server": {
    "name": "ubuntu-controller",
    "version": "1.0.0",
    "description": "MCP Server for Ubuntu System Control",
    "log_level": "INFO"
  },
  "security": {
    "policy_name": "safe",
    "allowed_paths": ["~/", "/tmp", "/var/tmp"],
    "forbidden_paths": ["/etc/passwd", "/etc/shadow", "/root"],
    "allowed_commands": ["ls", "cat", "echo", "apt", "git"],
    "forbidden_commands": ["rm", "dd", "shutdown", "reboot"],
    "max_command_timeout": 30,
    "allow_sudo": false
  }
}
```

### Environment Variables

- `MCP_LOG_LEVEL` - Set logging level (DEBUG, INFO, WARNING, ERROR)
- `MCP_POLICY` - Set security policy (safe, dev)
- `MCP_CONFIG_PATH` - Path to custom config file

## Example Usage with AI Assistants

### Claude Desktop Integration

Add to your Claude Desktop configuration file (usually located at `~/.config/claude-desktop/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ubuntu-controller": {
      "command": "/path/to/ubuntu_mcp_server/.venv/bin/python3",
      "args": ["/path/to/ubuntu_mcp_server/main.py"],
      "env": {
        "MCP_POLICY": "safe"
      }
    }
  }
}
```

**Important**: 
- Replace `/path/to/ubuntu_mcp_server/` with the actual absolute path to your project directory
- Use the **virtual environment Python interpreter** (`.venv/bin/python3`) to ensure all dependencies are available
- Both the `command` and `args` paths must be absolute paths

For example, if you cloned the project to `/home/username/ubuntu_mcp_server/`, the configuration would be:

```json
{
  "mcpServers": {
    "ubuntu-controller": {
      "command": "/home/username/ubuntu_mcp_server/.venv/bin/python3",
      "args": ["/home/username/ubuntu_mcp_server/main.py"],
      "env": {
        "MCP_POLICY": "safe"
      }
    }
  }
}
```

**Why use the virtual environment Python?**
The Ubuntu MCP Server requires the `mcp` package and other dependencies that are installed in the virtual environment. Using the system Python (`python3`) will result in import errors because it doesn't have access to these packages.

After adding this configuration:
1. Restart Claude Desktop
2. The Ubuntu Controller tools will be available in your conversations
3. You can ask Claude to perform system operations like "Check my disk space" or "List files in my home directory"

**Verification**: If the integration is successful, you should see "ubuntu-controller" listed as a connected server in Claude Desktop's status, and Claude will have access to system control tools.

### Example Interactions

Once connected to an AI assistant, you can request operations like:

**System Information**:
> "What's the current system status and available disk space?"

**File Management**:
> "List the contents of my home directory and show me the largest files"

**Development Tasks**:
> "Check if Node.js is installed, and if not, install it"

**Log Analysis**:
> "Look for any recent errors in the system logs" (requires dev policy)

## Security Considerations

### Production Deployment

For production use:

1. **Review security policies** carefully for your environment
2. **Use minimal permissions** - start with safe policy and expand as needed
3. **Monitor logs** for any suspicious activity
4. **Regular updates** of the server and dependencies
5. **Network isolation** if running remotely

### Security Features

- **Path traversal protection**: Prevents access outside allowed directories
- **Command injection prevention**: Validates and sanitizes all commands
- **Resource limits**: Timeouts and file size limits prevent resource exhaustion
- **Audit logging**: All operations are logged for security monitoring

## Development

### Adding New Tools

To add a new MCP tool, edit the `create_ubuntu_mcp_server` function:

```python
@mcp.tool("your_new_tool")
async def your_new_tool(param1: str, param2: int = 10) -> str:
    """Description of your tool
    
    Args:
        param1: Description of parameter
        param2: Optional parameter with default
        
    Returns:
        Description of return value
    """
    try:
        # Your implementation here
        result = controller.your_method(param1, param2)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
```

### Extending Security Policies

Create custom security policies by extending the `SecurityPolicy` class:

```python
def create_custom_policy() -> SecurityPolicy:
    return SecurityPolicy(
        allowed_paths=["/your/custom/paths"],
        forbidden_paths=["/sensitive/areas"],
        allowed_commands=["your", "allowed", "commands"],
        forbidden_commands=["dangerous", "commands"],
        max_command_timeout=60,
        allow_sudo=True  # Use with extreme caution
    )
```

### Testing

Run the comprehensive test suite:

```bash
# Test core functionality
python main.py --test

# Test MCP client integration
python test_client.py --simple

# Test with actual MCP protocol
python test_client.py
```

## Troubleshooting

### Common Issues

**Server starts then appears to hang**:
This is normal behavior! MCP servers are designed to run indefinitely and communicate via stdin/stdout. The server is waiting for MCP protocol messages from Claude Desktop or another MCP client.

**Import errors for MCP (`ModuleNotFoundError: No module named 'mcp'`)**:
This usually means Claude Desktop is trying to use the system Python instead of the virtual environment Python. Make sure your Claude Desktop configuration uses the full path to the virtual environment Python interpreter:
```json
"command": "/path/to/ubuntu_mcp_server/.venv/bin/python3"
```
NOT just `"command": "python3"`

If you still have issues:
```bash
# Activate virtual environment and reinstall
source .venv/bin/activate
pip install --upgrade mcp
```

**Permission denied errors**:
- Check that your user has access to the requested paths
- Verify security policy allows the operation
- For sudo operations, ensure `allow_sudo: true` in config

**Command timeout errors**:
- Increase `max_command_timeout` in security policy
- Check if command is hanging or requires interaction

**File not found errors**:
- Verify path is within allowed directories
- Check file permissions and existence

### Testing the Server

To verify the server works correctly:

```bash
# Test core functionality
python main.py --test

# Test server startup (should stay running)
python main.py --policy safe
# Press Ctrl+C to stop

# Test with development policy
python main.py --policy dev
```

### Debug Mode

Enable debug logging:

```bash
python main.py --log-level DEBUG
```

Or set environment variable:

```bash
export MCP_LOG_LEVEL=DEBUG
python main.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Code Style

- Follow PEP 8 style guidelines
- Add type hints for all functions
- Include comprehensive docstrings
- Write tests for new features

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Disclosure

If you discover a security vulnerability, please send an email to [security@yourproject.com] instead of creating a public issue.

## Changelog

### v1.0.0
- Initial release
- Core file and command operations
- Security policy system
- MCP protocol integration
- Package management tools
- Comprehensive testing suite
