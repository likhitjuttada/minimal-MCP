"""
SecureLocalMCP \u2014 MCP server entry point.

Starts a FastMCP server with sandboxed file operations and SSH terminal tools.
Uses stdio transport for local communication with MCP clients (Claude Desktop,
Claude Code, etc.).
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Ensure the project root is on sys.path so imports work when run directly
_project_root = str(Path(__file__).resolve().parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from sandbox import PathSandbox
from tools.file_ops import register_file_tools
from tools.ssh_ops import SSHConnectionPool, register_ssh_tools

# ======================================================================
# Logging
# ======================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("mcp.server")

# ======================================================================
# Configuration
# ======================================================================
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"


def _load_config() -> dict:
    """Load server configuration from config.json."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {CONFIG_PATH}\n"
            "Create config.json with allowed_directories and SSH settings."
        )
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ======================================================================
# Lifespan (startup / shutdown)
# ======================================================================

@dataclass
class AppContext:
    """Application context available to all tools during the server lifetime."""
    sandbox: PathSandbox
    ssh_pool: SSHConnectionPool
    config: dict


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialise resources on startup and clean up on shutdown."""
    config = _load_config()

    # Build the path sandbox
    allowed_dirs = [Path(d) for d in config.get("allowed_directories", [])]
    sandbox = PathSandbox(allowed_dirs)
    logger.info("Path sandbox initialised: %s", [str(r) for r in sandbox.allowed_roots])

    # Build the SSH connection pool
    max_conns = config.get("ssh", {}).get("max_connections", 5)
    ssh_pool = SSHConnectionPool(max_connections=max_conns)
    logger.info("SSH pool initialised (max %d connections)", max_conns)

    # Register tools
    register_file_tools(server, sandbox, config)
    register_ssh_tools(server, sandbox, config, ssh_pool)
    logger.info("All tools registered.")

    try:
        yield AppContext(sandbox=sandbox, ssh_pool=ssh_pool, config=config)
    finally:
        # Graceful shutdown \u2014 close all SSH sessions
        ssh_pool.close_all()
        logger.info("All SSH sessions closed. Server shutting down.")


# ======================================================================
# Server
# ======================================================================
mcp = FastMCP(
    "SecureLocalMCP",
    lifespan=app_lifespan,
)


def main() -> None:
    """Run the MCP server with stdio transport."""
    logger.info("Starting SecureLocalMCP server...")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
