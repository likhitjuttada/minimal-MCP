"""
Path sandboxing utility for the MCP server.

Ensures all file operations are strictly confined to a set of allowed
directories. Prevents path-traversal attacks, symlink escapes, UNC paths,
and Windows reserved device names.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


# Windows reserved device names that must never be used as path components.
_WINDOWS_RESERVED = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..+)?$",
    re.IGNORECASE,
)


class PathSandbox:
    """Validates that paths resolve strictly within allowed root directories.

    Usage:
        sandbox = PathSandbox([Path("C:/Users/likhi/Documents"), ...])
        safe = sandbox.validate("C:/Users/likhi/Documents/notes/todo.txt")
        # Returns the resolved Path if valid; raises PermissionError otherwise.
    """

    def __init__(self, allowed_roots: list[Path]) -> None:
        if not allowed_roots:
            raise ValueError("At least one allowed root directory is required.")

        self._allowed_roots: list[Path] = []
        for root in allowed_roots:
            resolved = Path(root).resolve()
            if not resolved.is_dir():
                raise ValueError(
                    f"Allowed root directory does not exist: {root}"
                )
            self._allowed_roots.append(resolved)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, user_path: str | Path) -> Path:
        """Resolve *user_path* and verify it lives inside the sandbox.

        Returns the resolved ``Path`` on success.
        Raises ``PermissionError`` on any violation.
        """
        if not user_path:
            raise PermissionError("Path must not be empty.")

        raw = str(user_path)

        # Block Windows extended-length / device paths (check BEFORE UNC
        # because \\.\  and \\?\  also start with \\)
        if raw.startswith("\\\\.\\") or raw.startswith("\\\\?\\"):
            raise PermissionError(
                f"Windows device paths are not allowed: {raw}"
            )

        # Block UNC paths  (\\server\share  or  //server/share)
        if raw.startswith("\\\\") or raw.startswith("//"):
            raise PermissionError(
                f"UNC paths are not allowed: {raw}"
            )

        # Block reserved device names anywhere in the path
        for part in Path(raw).parts:
            if _WINDOWS_RESERVED.match(part):
                raise PermissionError(
                    f"Windows reserved device name in path: {part}"
                )

        # Resolve to canonical absolute path (follows symlinks / junctions)
        resolved = Path(raw).resolve()

        # Must be under at least one allowed root
        for root in self._allowed_roots:
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue

        raise PermissionError(
            f"Access denied \u2014 path is outside the allowed directories: {resolved}"
        )

    def validate_pair(
        self, source: str | Path, destination: str | Path
    ) -> tuple[Path, Path]:
        """Validate both *source* and *destination* paths."""
        return self.validate(source), self.validate(destination)

    @property
    def allowed_roots(self) -> list[Path]:
        """Return a copy of the allowed root directories."""
        return list(self._allowed_roots)
