"""
Unit tests for the PathSandbox security module.

Tests cover:
- Valid paths inside the sandbox
- Path traversal attacks
- UNC path blocking
- Windows device path blocking
- Windows reserved name blocking
- Empty/None path rejection
- Pair validation
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# We need to add the project root to sys.path for imports
import sys

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from sandbox import PathSandbox


@pytest.fixture
def sandbox_dirs(tmp_path: Path) -> tuple[Path, Path]:
    """Create two temporary directories to serve as sandbox roots."""
    docs = tmp_path / "Documents"
    downloads = tmp_path / "Downloads"
    docs.mkdir()
    downloads.mkdir()
    return docs, downloads


@pytest.fixture
def sandbox(sandbox_dirs: tuple[Path, Path]) -> PathSandbox:
    """Create a PathSandbox with temp directories."""
    docs, downloads = sandbox_dirs
    return PathSandbox([docs, downloads])


# ======================================================================
# Valid paths \u2014 should be accepted
# ======================================================================

class TestValidPaths:
    """Paths that should pass validation."""

    def test_file_in_allowed_dir(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        test_file = docs / "test.txt"
        test_file.write_text("hello")
        result = sandbox.validate(str(test_file))
        assert result == test_file.resolve()

    def test_file_in_subdirectory(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        subdir = docs / "projects" / "myproject"
        subdir.mkdir(parents=True)
        test_file = subdir / "main.py"
        test_file.write_text("print('hello')")
        result = sandbox.validate(str(test_file))
        assert result == test_file.resolve()

    def test_directory_itself(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        result = sandbox.validate(str(docs))
        assert result == docs.resolve()

    def test_second_allowed_dir(self, sandbox: PathSandbox, sandbox_dirs):
        _, downloads = sandbox_dirs
        test_file = downloads / "report.pdf"
        test_file.write_text("content")
        result = sandbox.validate(str(test_file))
        assert result == test_file.resolve()

    def test_deeply_nested_path(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        deep = docs / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        test_file = deep / "deep.txt"
        test_file.write_text("deep")
        result = sandbox.validate(str(test_file))
        assert result == test_file.resolve()

    def test_path_object_input(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        test_file = docs / "test.txt"
        test_file.write_text("hello")
        result = sandbox.validate(test_file)  # Pass Path object, not string
        assert result == test_file.resolve()


# ======================================================================
# Invalid paths \u2014 should be rejected
# ======================================================================

class TestPathTraversal:
    """Path traversal attacks should be blocked."""

    def test_dotdot_escape(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        # Trying to escape the sandbox via ..
        escape = str(docs / ".." / ".." / "etc" / "passwd")
        with pytest.raises(PermissionError, match="outside the allowed"):
            sandbox.validate(escape)

    def test_parent_directory_blocked(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        parent = str(docs.parent)
        with pytest.raises(PermissionError, match="outside the allowed"):
            sandbox.validate(parent)

    def test_root_blocked(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="outside the allowed"):
            sandbox.validate("C:\\")

    def test_system_directory_blocked(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="outside the allowed"):
            sandbox.validate("C:\\Windows\\System32")

    def test_another_users_dir_blocked(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="outside the allowed"):
            sandbox.validate("C:\\Users\\someone_else\\Documents")


class TestUNCPaths:
    """UNC paths should be blocked."""

    def test_backslash_unc(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="UNC paths"):
            sandbox.validate("\\\\server\\share\\file.txt")

    def test_forward_slash_unc(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="UNC paths"):
            sandbox.validate("//server/share/file.txt")


class TestWindowsDevicePaths:
    """Windows device paths should be blocked."""

    def test_dot_device_path(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="device paths"):
            sandbox.validate("\\\\.\\PhysicalDrive0")

    def test_question_device_path(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="device paths"):
            sandbox.validate("\\\\?\\C:\\Windows")


class TestReservedNames:
    """Windows reserved device names should be blocked."""

    def test_con(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "CON"))

    def test_nul(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "NUL"))

    def test_com1(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "COM1"))

    def test_lpt1(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "LPT1"))

    def test_reserved_with_extension(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "CON.txt"))

    def test_reserved_case_insensitive(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        with pytest.raises(PermissionError, match="reserved device name"):
            sandbox.validate(str(docs / "con"))


class TestEmptyPaths:
    """Empty or None paths should be rejected."""

    def test_empty_string(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="must not be empty"):
            sandbox.validate("")

    def test_none(self, sandbox: PathSandbox):
        with pytest.raises(PermissionError, match="must not be empty"):
            sandbox.validate(None)  # type: ignore


class TestPairValidation:
    """The validate_pair method should check both paths."""

    def test_both_valid(self, sandbox: PathSandbox, sandbox_dirs):
        docs, downloads = sandbox_dirs
        src = docs / "source.txt"
        dst = downloads / "dest.txt"
        src.write_text("data")
        result_src, result_dst = sandbox.validate_pair(str(src), str(dst))
        assert result_src == src.resolve()
        assert result_dst == dst.resolve()

    def test_source_invalid(self, sandbox: PathSandbox, sandbox_dirs):
        _, downloads = sandbox_dirs
        with pytest.raises(PermissionError):
            sandbox.validate_pair("C:\\Windows\\System32\\cmd.exe", str(downloads / "x"))

    def test_destination_invalid(self, sandbox: PathSandbox, sandbox_dirs):
        docs, _ = sandbox_dirs
        src = docs / "source.txt"
        src.write_text("data")
        with pytest.raises(PermissionError):
            sandbox.validate_pair(str(src), "C:\\Windows\\evil.txt")


# ======================================================================
# Construction errors
# ======================================================================

class TestConstruction:
    """PathSandbox construction validation."""

    def test_empty_roots(self):
        with pytest.raises(ValueError, match="At least one"):
            PathSandbox([])

    def test_nonexistent_root(self, tmp_path: Path):
        fake = tmp_path / "nonexistent"
        with pytest.raises(ValueError, match="does not exist"):
            PathSandbox([fake])
