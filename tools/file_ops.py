"""
File operations tools for the MCP server.

Every tool validates paths through PathSandbox before performing any I/O.
Access is strictly limited to the directories listed in config.json.
"""

from __future__ import annotations

import datetime
import fnmatch
import os
import shutil
from pathlib import Path
from typing import Any

from sandbox import PathSandbox


def register_file_tools(mcp: Any, sandbox: PathSandbox, config: dict) -> None:
    """Register all file-operation tools on the given FastMCP instance."""

    max_read_size: int = config.get("max_file_read_size_bytes", 10 * 1024 * 1024)

    # ------------------------------------------------------------------
    # list_directory
    # ------------------------------------------------------------------
    @mcp.tool()
    def list_directory(path: str) -> dict:
        """List files and folders at the given path.

        Returns a dictionary with the directory path and a list of entries,
        each containing name, type (file/directory), size, and modified date.
        """
        resolved = sandbox.validate(path)

        if not resolved.is_dir():
            raise FileNotFoundError(f"Not a directory: {resolved}")

        entries = []
        for entry in sorted(resolved.iterdir()):
            stat = entry.stat()
            entries.append({
                "name": entry.name,
                "type": "directory" if entry.is_dir() else "file",
                "size_bytes": stat.st_size if entry.is_file() else None,
                "modified": datetime.datetime.fromtimestamp(
                    stat.st_mtime, tz=datetime.timezone.utc
                ).isoformat(),
            })

        return {"directory": str(resolved), "entries": entries}

    # ------------------------------------------------------------------
    # read_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def read_file(path: str, encoding: str = "utf-8") -> dict:
        """Read the contents of a text file.

        Args:
            path: Absolute or relative path to the file.
            encoding: Text encoding (default utf-8). Use 'binary' to read
                      raw bytes as a hex dump.

        Returns a dict with file path, size, and content (truncated if over
        the configured max_file_read_size_bytes).
        """
        resolved = sandbox.validate(path)

        if not resolved.is_file():
            raise FileNotFoundError(f"Not a file: {resolved}")

        size = resolved.stat().st_size
        truncated = size > max_read_size

        if encoding == "binary":
            data = resolved.read_bytes()[:max_read_size]
            content = data.hex()
        else:
            with open(resolved, "r", encoding=encoding, errors="replace") as fh:
                content = fh.read(max_read_size)

        return {
            "path": str(resolved),
            "size_bytes": size,
            "truncated": truncated,
            "content": content,
        }

    # ------------------------------------------------------------------
    # write_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def write_file(path: str, content: str, encoding: str = "utf-8") -> dict:
        """Write content to a file, creating parent directories if needed.

        Args:
            path: Absolute or relative path to the file.
            content: The text content to write.
            encoding: Text encoding (default utf-8).

        Returns confirmation with the written path and byte count.
        """
        resolved = sandbox.validate(path)
        resolved.parent.mkdir(parents=True, exist_ok=True)

        with open(resolved, "w", encoding=encoding) as fh:
            fh.write(content)

        return {
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding)),
        }

    # ------------------------------------------------------------------
    # create_directory
    # ------------------------------------------------------------------
    @mcp.tool()
    def create_directory(path: str) -> dict:
        """Create a directory (and any missing parents) at the given path.

        Returns confirmation with the created path.
        """
        resolved = sandbox.validate(path)
        resolved.mkdir(parents=True, exist_ok=True)
        return {"path": str(resolved), "created": True}

    # ------------------------------------------------------------------
    # delete_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def delete_file(path: str) -> dict:
        """Delete a single file.

        Returns confirmation with the deleted path.
        """
        resolved = sandbox.validate(path)

        if not resolved.is_file():
            raise FileNotFoundError(f"Not a file: {resolved}")

        resolved.unlink()
        return {"path": str(resolved), "deleted": True}

    # ------------------------------------------------------------------
    # delete_directory
    # ------------------------------------------------------------------
    @mcp.tool()
    def delete_directory(path: str, recursive: bool = False) -> dict:
        """Delete a directory.

        Args:
            path: Path to the directory.
            recursive: If True, delete the directory and all its contents.
                       If False (default), only delete if the directory is empty.

        Returns confirmation with the deleted path.
        """
        resolved = sandbox.validate(path)

        if not resolved.is_dir():
            raise FileNotFoundError(f"Not a directory: {resolved}")

        if recursive:
            shutil.rmtree(resolved)
        else:
            resolved.rmdir()  # Raises OSError if not empty

        return {"path": str(resolved), "deleted": True}

    # ------------------------------------------------------------------
    # move_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def move_file(source: str, destination: str) -> dict:
        """Move or rename a file or directory.

        Both source and destination must be within allowed directories.
        Returns the source and destination paths.
        """
        src, dst = sandbox.validate_pair(source, destination)

        if not src.exists():
            raise FileNotFoundError(f"Source does not exist: {src}")

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))

        return {"source": str(src), "destination": str(dst)}

    # ------------------------------------------------------------------
    # copy_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def copy_file(source: str, destination: str) -> dict:
        """Copy a file to a new location.

        Both source and destination must be within allowed directories.
        Returns the source and destination paths.
        """
        src, dst = sandbox.validate_pair(source, destination)

        if not src.is_file():
            raise FileNotFoundError(f"Source is not a file: {src}")

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dst))

        return {"source": str(src), "destination": str(dst)}

    # ------------------------------------------------------------------
    # file_info
    # ------------------------------------------------------------------
    @mcp.tool()
    def file_info(path: str) -> dict:
        """Get detailed information about a file or directory.

        Returns size, timestamps, and type.
        """
        resolved = sandbox.validate(path)

        if not resolved.exists():
            raise FileNotFoundError(f"Path does not exist: {resolved}")

        stat = resolved.stat()
        return {
            "path": str(resolved),
            "type": "directory" if resolved.is_dir() else "file",
            "size_bytes": stat.st_size,
            "created": datetime.datetime.fromtimestamp(
                stat.st_ctime, tz=datetime.timezone.utc
            ).isoformat(),
            "modified": datetime.datetime.fromtimestamp(
                stat.st_mtime, tz=datetime.timezone.utc
            ).isoformat(),
            "accessed": datetime.datetime.fromtimestamp(
                stat.st_atime, tz=datetime.timezone.utc
            ).isoformat(),
            "is_symlink": resolved.is_symlink(),
        }

    # ------------------------------------------------------------------
    # search_files
    # ------------------------------------------------------------------
    @mcp.tool()
    def search_files(
        directory: str, pattern: str, max_results: int = 100
    ) -> dict:
        """Search for files matching a glob pattern within a directory.

        Args:
            directory: The directory to search in.
            pattern: Glob pattern to match filenames (e.g. '*.txt', 'report*').
            max_results: Maximum number of results to return (default 100).

        Returns a dictionary with the search parameters and matching files.
        """
        resolved = sandbox.validate(directory)

        if not resolved.is_dir():
            raise FileNotFoundError(f"Not a directory: {resolved}")

        matches = []
        for root_dir, dirs, files in os.walk(resolved):
            for name in files + dirs:
                if fnmatch.fnmatch(name, pattern):
                    full_path = Path(root_dir) / name
                    # Ensure every result is also inside the sandbox
                    try:
                        sandbox.validate(str(full_path))
                    except PermissionError:
                        continue
                    matches.append(str(full_path))
                    if len(matches) >= max_results:
                        return {
                            "directory": str(resolved),
                            "pattern": pattern,
                            "matches": matches,
                            "truncated": True,
                        }

        return {
            "directory": str(resolved),
            "pattern": pattern,
            "matches": matches,
            "truncated": False,
        }
