# Security Guide \u2014 MCP Servers

This guide covers security considerations for MCP servers in general, and specific risks for servers that have SSH/shell access to remote machines.

---

## Part 1 \u2014 General MCP Server Security

### 1. Principle of Least Privilege

> **Rule**: Give the server access to *only* what it needs. Nothing more.

- **File access**: Restrict to specific directories (this server uses a strict allow-list).
- **Network access**: Only connect to pre-approved hosts.
- **OS permissions**: Run the server as a regular user, never as Administrator/root.
- **Tool scope**: Each tool should do one thing. Don't create "god tools" that can do everything.

**Why it matters**: If an AI agent is tricked (via prompt injection or adversarial input) into running a dangerous command, least privilege limits the blast radius.

### 2. Input Validation & Sanitisation

> **Rule**: Never trust input from the AI model. Validate everything.

- **Paths**: Always resolve to absolute paths and verify they're inside the sandbox. This server blocks `..` traversal, symlinks, UNC paths, and Windows reserved names.
- **Commands**: Never interpolate user strings directly into shell commands. Use parameterised execution (`subprocess.run([...], shell=False)` or paramiko's `exec_command`).
- **Types**: Validate argument types, ranges, and lengths before processing.

**Why it matters**: LLMs can be manipulated through prompt injection. A malicious document might instruct the model to "read /etc/passwd" or "delete all files". Your server is the last line of defence.

### 3. Path Traversal Prevention

> **Rule**: Always resolve paths to their canonical form before checking permissions.

Common attacks this server prevents:
- `../../etc/passwd` \u2014 relative traversal
- `\\server\share\` \u2014 UNC paths to network resources
- `\\.\PhysicalDrive0` \u2014 Windows device paths
- `CON`, `NUL`, `COM1` \u2014 Windows reserved device names
- Symlinks/junctions pointing outside the sandbox

**Implementation pattern**:
```python
resolved = Path(user_input).resolve()  # Follows symlinks, resolves ..
if not any(resolved.is_relative_to(root) for root in allowed_roots):
    raise PermissionError("Access denied")
```

### 4. Resource Limits

> **Rule**: Cap everything \u2014 file sizes, output lengths, connection counts, timeouts.

Without limits, a single malicious request can:
- Read a 100 GB file into memory \u2192 crash the server
- Run a command that produces infinite output \u2192 memory exhaustion
- Open hundreds of connections \u2192 resource exhaustion
- Run a command that never finishes \u2192 hang the server

This server enforces:
| Resource | Default Limit |
|----------|------|
| File read size | 10 MB |
| SSH output size | 1 MB |
| Command length | 8,192 chars |
| Command timeout | 30 s (max 300 s) |
| SSH connections | 5 concurrent |

### 5. Transport Security

> **Rule**: Local servers use stdio. If you need HTTP, bind to 127.0.0.1 only.

- **stdio** (this server): Communication happens through stdin/stdout. No network exposure, no attack surface from the network. This is the safest transport for local MCP servers.
- **HTTP/SSE**: If you must use HTTP, bind to `127.0.0.1` (localhost), not `0.0.0.0` (all interfaces). Use HTTPS with TLS certificates for any non-local communication. Validate Origin and Host headers for CSRF protection.

### 6. Logging & Audit Trails

> **Rule**: Log every action with enough detail to reconstruct what happened.

This server logs:
- Every SSH connection (host, user, timestamp)
- Every command execution (command hash, not the full command \u2014 to avoid logging secrets)
- Every file transfer (paths, byte counts)
- Every security violation (blocked commands, path escapes)

**Best practices**:
- Log to stderr (not stdout \u2014 that's the MCP channel)
- Include timestamps and session IDs
- Don't log sensitive data (passwords, key contents, file contents)
- Consider shipping logs to a central logging system for production use

### 7. Error Handling

> **Rule**: Never expose internal state, stack traces, or file paths in error messages returned to the model.

- Return user-friendly error messages (e.g., "Access denied" not "PermissionError at /internal/path/sandbox.py:53")
- Log detailed errors server-side for debugging
- Don't reveal which paths exist vs. don't exist (information leakage)
- Catch all exceptions in tool handlers \u2014 an unhandled exception can crash the server

### 8. Dependency Management

> **Rule**: Pin your dependencies and audit them regularly.

- Use `uv.lock` or `pip freeze` to pin exact versions
- Audit dependencies for known vulnerabilities (`pip-audit`, `safety`)
- Minimise dependencies \u2014 each one is an attack surface
- This server uses only 2 runtime dependencies: `mcp` and `paramiko`

---

## Part 2 \u2014 MCP Servers with SSH / Shell Access

### \u26a0\ufe0f Why SSH in MCP Is High-Risk

An MCP server with SSH access is essentially giving the AI model a **terminal on a remote machine**. This is the most powerful \u2014 and most dangerous \u2014 capability an MCP server can have.

**The threat model**:
1. **Prompt injection**: A malicious document or website could instruct the model to run destructive commands.
2. **Model hallucination**: The model might generate a plausible but wrong command (e.g., `rm -rf /` instead of `rm -rf ./build/`).
3. **Lateral movement**: If the SSH user has access to other systems, a compromised session could be used to pivot.
4. **Data exfiltration**: The model could be tricked into reading sensitive files and outputting them.

### 9. Host Allow-Listing

> **Rule**: Maintain an explicit list of approved SSH hosts. Block everything else.

```json
"allowed_hosts": ["dev-server.internal", "192.168.1.100"]
```

- Never allow connections to arbitrary hosts
- Review the allow-list periodically
- Consider separate allow-lists for different sensitivity levels

### 10. SSH Key Management

> **Rule**: Use SSH keys, never passwords. Protect the keys.

**Best practices**:
- Generate keys with strong algorithms (`ssh-keygen -t ed25519`)
- Use a passphrase on the key (even though it adds complexity)
- Store keys with restrictive permissions (`chmod 600 ~/.ssh/id_ed25519`)
- Use separate keys for MCP server access vs. personal access
- Rotate keys regularly
- Consider using `ssh-agent` with key lifetime limits (`ssh-add -t 3600`)
- **Never** embed keys in code or configuration files checked into Git

### 11. Command Injection Prevention

> **Rule**: Block known-dangerous commands and limit what the model can execute.

This server implements a **command blocklist**:
```json
"blocked_commands": ["rm -rf /", "mkfs", "dd if=", "shutdown", "reboot"]
```

**Limitations**: A blocklist is **defence-in-depth**, not a sandbox. It catches obvious mistakes but cannot prevent all harmful commands. The real protection is:
1. **The SSH user's permissions** \u2014 use a dedicated user account with minimal privileges
2. **sudo restrictions** \u2014 never give the MCP SSH user passwordless sudo
3. **Remote OS controls** \u2014 AppArmor/SELinux profiles, read-only filesystems

### 12. Output Sanitisation

> **Rule**: Cap output size and be aware of what's being returned to the model.

Risks:
- **Memory exhaustion**: A `cat /dev/zero` could produce infinite output
- **Sensitive data leakage**: Command output might contain secrets, tokens, or private data that the model then includes in its response to the user
- **Token exhaustion**: Huge outputs waste the model's context window

Mitigations:
- Cap output at a fixed size (this server: 1 MB)
- Consider filtering known-sensitive patterns (API keys, passwords) from output
- Log a warning when output is truncated

### 13. Session Lifecycle Management

> **Rule**: Don't leave SSH sessions open indefinitely.

- Set a maximum session lifetime (e.g., 1 hour)
- Clean up all sessions on server shutdown (this server does this in the lifespan handler)
- Limit concurrent connections (this server: max 5)
- Consider idle timeout \u2014 disconnect sessions with no activity for N minutes

### 14. Network Segmentation

> **Rule**: The remote servers you SSH into should be in a controlled network zone.

- Don't point MCP SSH at production databases or customer-facing servers
- Use a bastion/jump host pattern for access to sensitive environments
- The SSH user should only have access to what the AI agent needs
- Consider a dedicated "agent" user on remote servers with restricted shell, read-only access to logs, etc.

### 15. Monitoring & Alerting

> **Rule**: Watch for anomalous behaviour and alert on it.

Monitor for:
- Unusual command patterns (many rapid commands, commands at odd hours)
- Failed connection attempts
- Commands in the blocklist being attempted
- Large file transfers
- Connections to new/unexpected hosts

---

## Quick Reference \u2014 Security Checklist

| Category | Check | Status |
|----------|-------|--------|
| File Access | Paths validated through sandbox | \u2705 |
| File Access | Parent directories blocked | \u2705 |
| File Access | UNC / device paths blocked | \u2705 |
| File Access | Symlink escapes prevented | \u2705 |
| File Access | Read size capped | \u2705 |
| SSH | Host allow-list enforced | \u2705 |
| SSH | Key-based auth only | \u2705 |
| SSH | Command blocklist | \u2705 |
| SSH | Command length limit | \u2705 |
| SSH | Execution timeout | \u2705 |
| SSH | Output truncation | \u2705 |
| SSH | Connection limit | \u2705 |
| SSH | Graceful shutdown cleanup | \u2705 |
| SSH | Structured logging | \u2705 |
| Transport | stdio (no network exposure) | \u2705 |
| General | Error messages don't leak internals | \u2705 |
| General | Dependencies minimised & pinned | \u2705 |

---

## Further Reading

- [MCP Specification](https://modelcontextprotocol.io) \u2014 Official protocol documentation
- [MCP Security Guidelines](https://modelcontextprotocol.io/specification/2025-03-26/basic/security) \u2014 Protocol-level security considerations
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection) \u2014 Prevention techniques
- [SSH Hardening Guide](https://www.sshaudit.com/) \u2014 Audit your SSH configuration
