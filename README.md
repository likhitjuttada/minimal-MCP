# SecureLocalMCP

A secure MCP server with **sandboxed file access** and **SSH terminal capabilities**, built with the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Features

### File Operations (sandboxed)
- **Strictly limited** to `C:\Users\likhi\Documents` and `C:\Users\likhi\Downloads`
- Parent directories (`C:\Users\likhi`, `C:\Users`, `C:\`, etc.) are **not accessible**
- Path-traversal, symlink escapes, UNC paths, and Windows device names are all blocked
- 10 tools: list, read, write, create dir, delete file/dir, move, copy, info, search

### SSH Terminal (full context for AI agents)
- Persistent SSH sessions with connection pooling
- Execute commands with stdout + stderr + exit code
- Working-directory awareness (`ssh_execute(..., working_dir="/app")`)
- Stream long command output (builds, installs)
- Read/write remote files via SFTP
- Local port-forwarding through SSH tunnels
- 12 tools total

### Security Hardening
- Host allow-list for SSH connections
- Key-based authentication (setup once, then seamless)
- Destructive command blocklist
- Output truncation (1 MB cap)
- Connection limits (max 5 concurrent)
- Structured logging of all SSH operations

## Quick Start

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Install
```bash
cd c:\Users\likhi\Documents\minimal-MCP
uv sync
```

### Configure

Edit `config.json`:

1. **Allowed directories** \u2014 already set to Documents and Downloads
2. **SSH hosts** \u2014 add your remote servers:
   ```json
   "allowed_hosts": ["your-server.example.com", "192.168.1.100"]
   ```
3. **SSH key** \u2014 set if not using default `~/.ssh/id_ed25519`:
   ```json
   "default_key_path": "C:\\Users\\likhi\\.ssh\\my_key"
   ```

### Run

**With MCP Inspector (for testing):**
```bash
uv run mcp dev server.py
```

**Direct execution:**
```bash
uv run python server.py
```

**Install in Claude Desktop:**
```bash
uv run mcp install server.py --name "SecureLocalMCP"
```

**Add to Claude Code:**
```bash
claude mcp add secure-local-mcp -- uv run python c:\Users\likhi\Documents\minimal-MCP\server.py
```

## SSH Setup (One-Time)

If you haven't set up SSH key authentication before:

```bash
# 1. Generate a key pair (if you don't have one)
ssh-keygen -t ed25519 -C "your-email@example.com"

# 2. Copy the public key to your remote server
ssh-copy-id username@your-server.example.com

# 3. Test the connection (should connect without a password)
ssh username@your-server.example.com

# 4. Add the host to config.json allowed_hosts
```

## Security

See [SECURITY.md](./SECURITY.md) for a comprehensive security guide covering:
- General MCP server security principles
- SSH-specific risks and mitigations
- Best practices for MCP servers with shell access

## Project Structure

```
minimal-MCP/
\u251c\u2500\u2500 server.py          # FastMCP entry point (stdio transport)
\u251c\u2500\u2500 sandbox.py         # Path-sandboxing security module
\u251c\u2500\u2500 config.json        # Configuration (allowed dirs, SSH settings)
\u251c\u2500\u2500 tools/
\u2502   \u251c\u2500\u2500 file_ops.py    # 10 file-operation tools
\u2502   \u2514\u2500\u2500 ssh_ops.py     # 12 SSH terminal tools
\u251c\u2500\u2500 tests/
\u2502   \u2514\u2500\u2500 test_sandbox.py
\u251c\u2500\u2500 SECURITY.md        # Security guide
\u2514\u2500\u2500 README.md          # This file
```
