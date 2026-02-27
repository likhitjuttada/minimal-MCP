"""
SSH operations tools for the MCP server.

Provides persistent shell sessions so an AI agent gets full terminal-like
context: run commands, see output, track working directory, read/write
remote files, and port-forward \u2014 all with comprehensive security hardening.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import paramiko

from sandbox import PathSandbox

logger = logging.getLogger("mcp.ssh")


# ======================================================================
# Data structures
# ======================================================================

@dataclass
class SSHSession:
    """Represents one persistent SSH connection."""

    connection_id: str
    host: str
    port: int
    username: str
    client: paramiko.SSHClient
    connected_at: float = field(default_factory=time.time)


class SSHConnectionPool:
    """Thread-safe pool of SSH sessions with a configurable limit."""

    def __init__(self, max_connections: int = 5) -> None:
        self._sessions: dict[str, SSHSession] = {}
        self._max = max_connections
        self._lock = threading.Lock()

    def add(self, session: SSHSession) -> None:
        with self._lock:
            if len(self._sessions) >= self._max:
                raise ConnectionError(
                    f"Maximum SSH connections ({self._max}) reached. "
                    "Disconnect an existing session first."
                )
            self._sessions[session.connection_id] = session

    def get(self, connection_id: str) -> SSHSession:
        with self._lock:
            session = self._sessions.get(connection_id)
        if session is None:
            raise KeyError(f"No SSH session with id: {connection_id}")
        return session

    def remove(self, connection_id: str) -> SSHSession:
        with self._lock:
            session = self._sessions.pop(connection_id, None)
        if session is None:
            raise KeyError(f"No SSH session with id: {connection_id}")
        return session

    def all(self) -> list[SSHSession]:
        with self._lock:
            return list(self._sessions.values())

    def close_all(self) -> None:
        with self._lock:
            for session in self._sessions.values():
                try:
                    session.client.close()
                except Exception:
                    pass
            self._sessions.clear()


# ======================================================================
# Security helpers
# ======================================================================

def _check_host_allowed(host: str, allowed_hosts: list[str]) -> None:
    """Raise PermissionError if host is not in the allow-list."""
    if not allowed_hosts:
        raise PermissionError(
            "No SSH hosts are configured in config.json. "
            "Add hosts to 'ssh.allowed_hosts' before connecting."
        )
    if host not in allowed_hosts:
        raise PermissionError(
            f"Host '{host}' is not in the SSH allow-list. "
            f"Allowed hosts: {allowed_hosts}"
        )


def _check_command(
    command: str,
    blocked_patterns: list[str],
    max_length: int,
) -> None:
    """Raise PermissionError if command matches a blocked pattern."""
    if len(command) > max_length:
        raise PermissionError(
            f"Command exceeds maximum length ({max_length} chars)."
        )
    cmd_lower = command.lower().strip()
    for pattern in blocked_patterns:
        if pattern.lower() in cmd_lower:
            raise PermissionError(
                f"Command blocked by security policy (matched: '{pattern}'). "
                "This command is considered destructive."
            )


def _truncate_output(output: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate output to max_bytes, returning (text, was_truncated)."""
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return output, False
    return encoded[:max_bytes].decode("utf-8", errors="replace"), True


def _resolve_key_path(key_path: str | None, config: dict) -> str | None:
    """Resolve the SSH private key path from explicit arg or config defaults."""
    if key_path:
        return key_path

    # Try config default
    default = config.get("ssh", {}).get("default_key_path")
    if default and Path(default).expanduser().exists():
        return str(Path(default).expanduser())

    # Auto-discover common key locations
    for candidate in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa"]:
        p = Path(candidate).expanduser()
        if p.exists():
            return str(p)

    return None  # Will fall back to ssh-agent


# ======================================================================
# Tool registration
# ======================================================================

def register_ssh_tools(
    mcp: Any,
    sandbox: PathSandbox,
    config: dict,
    pool: SSHConnectionPool,
) -> None:
    """Register all SSH-operation tools on the given FastMCP instance."""

    ssh_config: dict = config.get("ssh", {})
    allowed_hosts: list[str] = ssh_config.get("allowed_hosts", [])
    blocked_commands: list[str] = ssh_config.get("blocked_commands", [])
    default_timeout: int = ssh_config.get("default_timeout_seconds", 30)
    max_timeout: int = ssh_config.get("max_timeout_seconds", 300)
    max_output: int = ssh_config.get("max_output_bytes", 1_048_576)
    max_cmd_len: int = ssh_config.get("max_command_length", 8192)

    # ------------------------------------------------------------------
    # ssh_connect
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_connect(
        host: str,
        username: str,
        port: int = 22,
        key_path: str | None = None,
    ) -> dict:
        """Open a persistent SSH session to a remote server.

        Args:
            host: Hostname or IP address (must be in config allow-list).
            username: SSH username.
            port: SSH port (default 22).
            key_path: Path to SSH private key file. If omitted, uses the
                      config default or auto-discovers ~/.ssh/id_ed25519
                      or ~/.ssh/id_rsa, or falls back to ssh-agent.

        Returns a connection_id to use with all other SSH tools.
        """
        _check_host_allowed(host, allowed_hosts)

        resolved_key = _resolve_key_path(key_path, config)

        client = paramiko.SSHClient()
        # Accept unknown host keys (the allow-list is the trust boundary).
        # For production use, consider using a known_hosts file instead.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": 15,
        }

        if resolved_key:
            connect_kwargs["key_filename"] = resolved_key
        else:
            # Fall back to ssh-agent
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

        try:
            client.connect(**connect_kwargs)
        except Exception as exc:
            client.close()
            raise ConnectionError(
                f"Failed to connect to {host}:{port} as {username}: {exc}"
            ) from exc

        connection_id = str(uuid.uuid4())[:8]
        session = SSHSession(
            connection_id=connection_id,
            host=host,
            port=port,
            username=username,
            client=client,
        )
        pool.add(session)

        logger.info(
            "SSH connected: id=%s host=%s user=%s",
            connection_id, host, username,
        )

        return {
            "connection_id": connection_id,
            "host": host,
            "port": port,
            "username": username,
            "message": f"Connected to {host}:{port} as {username}",
        }

    # ------------------------------------------------------------------
    # ssh_disconnect
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_disconnect(connection_id: str) -> dict:
        """Gracefully close an SSH session.

        Args:
            connection_id: The session ID returned by ssh_connect.
        """
        session = pool.remove(connection_id)
        session.client.close()
        logger.info(
            "SSH disconnected: id=%s host=%s", connection_id, session.host
        )
        return {
            "connection_id": connection_id,
            "host": session.host,
            "message": "Disconnected successfully.",
        }

    # ------------------------------------------------------------------
    # ssh_list_connections
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_list_connections() -> dict:
        """List all active SSH sessions.

        Returns connection details including id, host, user, and uptime.
        """
        sessions = pool.all()
        return {
            "count": len(sessions),
            "connections": [
                {
                    "connection_id": s.connection_id,
                    "host": s.host,
                    "port": s.port,
                    "username": s.username,
                    "uptime_seconds": round(time.time() - s.connected_at, 1),
                }
                for s in sessions
            ],
        }

    # ------------------------------------------------------------------
    # ssh_execute
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_execute(
        connection_id: str,
        command: str,
        timeout: int | None = None,
        working_dir: str | None = None,
    ) -> dict:
        """Execute a command on the remote server.

        Args:
            connection_id: The session ID.
            command: The shell command to run.
            timeout: Execution timeout in seconds (default from config).
            working_dir: Optional directory to cd into before executing.

        Returns stdout, stderr, exit_code, and truncation info.
        """
        session = pool.get(connection_id)
        _check_command(command, blocked_commands, max_cmd_len)

        effective_timeout = min(timeout or default_timeout, max_timeout)

        # Prepend cd if working_dir is specified
        full_command = command
        if working_dir:
            # Escape single quotes in the directory path
            safe_dir = working_dir.replace("'", "'\\''")
            full_command = f"cd '{safe_dir}' && {command}"

        logger.info(
            "SSH exec: id=%s host=%s cmd_hash=%s",
            connection_id,
            session.host,
            hashlib.sha256(command.encode()).hexdigest()[:12],
        )

        try:
            stdin, stdout, stderr = session.client.exec_command(
                full_command, timeout=effective_timeout
            )
            exit_code = stdout.channel.recv_exit_status()

            raw_stdout = stdout.read().decode("utf-8", errors="replace")
            raw_stderr = stderr.read().decode("utf-8", errors="replace")

            out, out_truncated = _truncate_output(raw_stdout, max_output)
            err, err_truncated = _truncate_output(raw_stderr, max_output)

        except Exception as exc:
            return {
                "connection_id": connection_id,
                "command": command,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(exc),
                "error": True,
            }

        return {
            "connection_id": connection_id,
            "command": command,
            "working_dir": working_dir,
            "exit_code": exit_code,
            "stdout": out,
            "stderr": err,
            "stdout_truncated": out_truncated,
            "stderr_truncated": err_truncated,
        }

    # ------------------------------------------------------------------
    # ssh_execute_stream
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_execute_stream(
        connection_id: str,
        command: str,
        timeout: int | None = None,
        chunk_size: int = 65536,
    ) -> dict:
        """Execute a long-running command and return output in chunks.

        Useful for builds, installs, or any command with large output.

        Args:
            connection_id: The session ID.
            command: The shell command to run.
            timeout: Execution timeout in seconds.
            chunk_size: Bytes per output chunk (default 64KB).

        Returns the full collected output, exit code, and chunk count.
        """
        session = pool.get(connection_id)
        _check_command(command, blocked_commands, max_cmd_len)

        effective_timeout = min(timeout or default_timeout, max_timeout)

        logger.info(
            "SSH stream exec: id=%s host=%s cmd_hash=%s",
            connection_id,
            session.host,
            hashlib.sha256(command.encode()).hexdigest()[:12],
        )

        try:
            stdin, stdout, stderr = session.client.exec_command(
                command, timeout=effective_timeout
            )

            output_chunks: list[str] = []
            total_bytes = 0
            truncated = False

            while True:
                chunk = stdout.channel.recv(chunk_size)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                total_bytes += len(chunk)
                if total_bytes > max_output:
                    truncated = True
                    break
                output_chunks.append(decoded)

            exit_code = stdout.channel.recv_exit_status()
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            err_out, err_truncated = _truncate_output(stderr_text, max_output)

        except Exception as exc:
            return {
                "connection_id": connection_id,
                "command": command,
                "exit_code": -1,
                "output": str(exc),
                "error": True,
            }

        return {
            "connection_id": connection_id,
            "command": command,
            "exit_code": exit_code,
            "output": "".join(output_chunks),
            "stderr": err_out,
            "output_truncated": truncated,
            "stderr_truncated": err_truncated,
            "chunks_received": len(output_chunks),
        }

    # ------------------------------------------------------------------
    # ssh_get_cwd
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_get_cwd(connection_id: str) -> dict:
        """Get the default working directory on the remote server.

        Returns the home/default directory for the SSH user.
        """
        session = pool.get(connection_id)

        stdin, stdout, stderr = session.client.exec_command(
            "pwd", timeout=10
        )
        cwd = stdout.read().decode("utf-8", errors="replace").strip()

        return {
            "connection_id": connection_id,
            "cwd": cwd,
        }

    # ------------------------------------------------------------------
    # ssh_upload
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_upload(
        connection_id: str, local_path: str, remote_path: str
    ) -> dict:
        """Upload a local file to the remote server via SFTP.

        Args:
            connection_id: The session ID.
            local_path: Path to the local file (must be within sandbox).
            remote_path: Destination path on the remote server.

        Returns confirmation with paths and transferred bytes.
        """
        session = pool.get(connection_id)
        resolved_local = sandbox.validate(local_path)

        if not resolved_local.is_file():
            raise FileNotFoundError(f"Local file not found: {resolved_local}")

        sftp = session.client.open_sftp()
        try:
            sftp.put(str(resolved_local), remote_path)
            remote_stat = sftp.stat(remote_path)
            transferred = remote_stat.st_size
        finally:
            sftp.close()

        logger.info(
            "SSH upload: id=%s local=%s remote=%s bytes=%d",
            connection_id, resolved_local, remote_path, transferred or 0,
        )

        return {
            "connection_id": connection_id,
            "local_path": str(resolved_local),
            "remote_path": remote_path,
            "bytes_transferred": transferred,
        }

    # ------------------------------------------------------------------
    # ssh_download
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_download(
        connection_id: str, remote_path: str, local_path: str
    ) -> dict:
        """Download a file from the remote server to a local path via SFTP.

        Args:
            connection_id: The session ID.
            remote_path: Path on the remote server.
            local_path: Destination path locally (must be within sandbox).

        Returns confirmation with paths and transferred bytes.
        """
        session = pool.get(connection_id)
        resolved_local = sandbox.validate(local_path)

        resolved_local.parent.mkdir(parents=True, exist_ok=True)

        sftp = session.client.open_sftp()
        try:
            sftp.get(remote_path, str(resolved_local))
        finally:
            sftp.close()

        transferred = resolved_local.stat().st_size

        logger.info(
            "SSH download: id=%s remote=%s local=%s bytes=%d",
            connection_id, remote_path, resolved_local, transferred,
        )

        return {
            "connection_id": connection_id,
            "remote_path": remote_path,
            "local_path": str(resolved_local),
            "bytes_transferred": transferred,
        }

    # ------------------------------------------------------------------
    # ssh_read_remote_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_read_remote_file(
        connection_id: str,
        remote_path: str,
        encoding: str = "utf-8",
    ) -> dict:
        """Read the contents of a file on the remote server.

        Args:
            connection_id: The session ID.
            remote_path: Path to the file on the remote server.
            encoding: Text encoding (default utf-8).

        Returns the file content (truncated if over max_output_bytes).
        """
        session = pool.get(connection_id)

        sftp = session.client.open_sftp()
        try:
            remote_stat = sftp.stat(remote_path)
            size = remote_stat.st_size

            with sftp.open(remote_path, "r") as f:
                raw = f.read(max_output)
                content = raw.decode(encoding, errors="replace") if isinstance(raw, bytes) else raw
        finally:
            sftp.close()

        truncated = size > max_output

        return {
            "connection_id": connection_id,
            "remote_path": remote_path,
            "size_bytes": size,
            "truncated": truncated,
            "content": content,
        }

    # ------------------------------------------------------------------
    # ssh_write_remote_file
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_write_remote_file(
        connection_id: str,
        remote_path: str,
        content: str,
        encoding: str = "utf-8",
    ) -> dict:
        """Write content to a file on the remote server.

        Args:
            connection_id: The session ID.
            remote_path: Destination file path on the remote server.
            content: The text content to write.
            encoding: Text encoding (default utf-8).

        Returns confirmation with path and byte count.
        """
        session = pool.get(connection_id)

        data = content.encode(encoding)
        sftp = session.client.open_sftp()
        try:
            with sftp.open(remote_path, "wb") as f:
                f.write(data)
        finally:
            sftp.close()

        logger.info(
            "SSH write: id=%s remote=%s bytes=%d",
            connection_id, remote_path, len(data),
        )

        return {
            "connection_id": connection_id,
            "remote_path": remote_path,
            "bytes_written": len(data),
        }

    # ------------------------------------------------------------------
    # ssh_list_remote
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_list_remote(
        connection_id: str, remote_path: str = "."
    ) -> dict:
        """List the contents of a directory on the remote server.

        Args:
            connection_id: The session ID.
            remote_path: Directory path on the remote server (default: cwd).

        Returns a list of entries with name, size, and modified date.
        """
        session = pool.get(connection_id)

        sftp = session.client.open_sftp()
        try:
            entries = []
            for attr in sftp.listdir_attr(remote_path):
                import stat as stat_module

                is_dir = stat_module.S_ISDIR(attr.st_mode) if attr.st_mode else False
                entries.append({
                    "name": attr.filename,
                    "type": "directory" if is_dir else "file",
                    "size_bytes": attr.st_size,
                    "modified": attr.st_mtime,
                })
        finally:
            sftp.close()

        return {
            "connection_id": connection_id,
            "remote_path": remote_path,
            "entries": entries,
        }

    # ------------------------------------------------------------------
    # ssh_port_forward
    # ------------------------------------------------------------------
    @mcp.tool()
    def ssh_port_forward(
        connection_id: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> dict:
        """Set up local port-forwarding through the SSH tunnel.

        Traffic sent to localhost:local_port will be forwarded to
        remote_host:remote_port through the SSH connection.

        Args:
            connection_id: The session ID.
            local_port: The local port to listen on.
            remote_host: The remote host to forward to (from the SSH server's
                         perspective).
            remote_port: The port on the remote host.

        Returns confirmation with the forwarding details.
        """
        session = pool.get(connection_id)
        transport = session.client.get_transport()

        if transport is None:
            raise ConnectionError(
                f"SSH transport not available for connection {connection_id}"
            )

        # Request port forwarding via the paramiko transport
        # This sets up a direct-tcpip channel, not a reverse tunnel
        import socket
        import selectors

        forward_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        forward_server.bind(("127.0.0.1", local_port))
        forward_server.listen(1)
        forward_server.setblocking(False)

        def _forward_handler():
            """Accept connections and forward them through the SSH tunnel."""
            sel = selectors.DefaultSelector()
            sel.register(forward_server, selectors.EVENT_READ)

            while True:
                try:
                    events = sel.select(timeout=1)
                    for key, _ in events:
                        if key.fileobj is forward_server:
                            client_sock, addr = forward_server.accept()
                            try:
                                channel = transport.open_channel(
                                    "direct-tcpip",
                                    (remote_host, remote_port),
                                    addr,
                                )
                            except Exception:
                                client_sock.close()
                                continue

                            if channel is None:
                                client_sock.close()
                                continue

                            # Bi-directional forwarding
                            _bidirectional_forward(client_sock, channel)
                except Exception:
                    break

        def _bidirectional_forward(sock, channel):
            """Forward data between sock and channel in a background thread."""
            import select

            def _pipe():
                while True:
                    r, _, _ = select.select([sock, channel], [], [], 1)
                    if sock in r:
                        data = sock.recv(65536)
                        if not data:
                            break
                        channel.send(data)
                    if channel in r:
                        data = channel.recv(65536)
                        if not data:
                            break
                        sock.send(data)
                sock.close()
                channel.close()

            t = threading.Thread(target=_pipe, daemon=True)
            t.start()

        thread = threading.Thread(target=_forward_handler, daemon=True)
        thread.start()

        logger.info(
            "SSH port forward: id=%s local=%d -> %s:%d",
            connection_id, local_port, remote_host, remote_port,
        )

        return {
            "connection_id": connection_id,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "message": (
                f"Port forwarding active: localhost:{local_port} -> "
                f"{remote_host}:{remote_port} via SSH tunnel"
            ),
        }
