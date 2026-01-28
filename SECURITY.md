# Security

This document describes agentmon's security posture, known issues, and hardening recommendations.

## Threat Model

Agentmon is a network monitoring tool that:
- Receives untrusted input (syslog messages from network devices)
- Stores data in a local database
- Optionally sends data to external services (Slack, Ollama)
- Optionally connects to remote systems (Pi-hole via SSH)

### Attack Surface

| Component | Exposure | Threats |
|-----------|----------|---------|
| Syslog receiver | Network (configurable) | Log injection, DoS, reconnaissance |
| Config files | Local filesystem | Credential theft, config tampering |
| Database | Local filesystem | Data exfiltration, tampering, privacy exposure |
| SSH collector | Outbound to Pi-hole | Credential exposure, command injection |
| Slack notifier | Outbound HTTPS | Webhook credential theft |
| LLM classifier | Local (Ollama) | Prompt injection |
| Device activity baseline | Local database | Activity pattern exposure, privacy concerns |

## Security Audit Status

Last audit: 2025-01-28

### Fixed Issues

| Severity | Issue | Fix |
|----------|-------|-----|
| CRITICAL | SQL f-string interpolation in time queries | Use datetime arithmetic with parameterized queries |
| CRITICAL | Syslog default bind 0.0.0.0 | Changed default to 127.0.0.1 (localhost) |
| HIGH | LLM prompt injection via domain names | Input sanitization + prompt hardening |

### Known Issues (TODO)

#### HIGH: SSH Command Injection

**Location:** `agentmon/collectors/pihole.py:165`

**Risk:** If an attacker controls the config file, they can inject shell commands that execute on the remote Pi-hole server via the `remote_db_path` setting.

**Mitigation:** Use `shlex.quote()` for shell escaping:
```python
import shlex
cmd = f'sqlite3 -separator "|" {shlex.quote(self.config.remote_db_path)} {shlex.quote(sql)}'
```

#### HIGH: Slack Webhook in Plaintext Config

**Location:** `agentmon/config.py:74`

**Risk:** Slack webhook URLs function as bearer tokens. Anyone with read access to config files can steal and misuse them.

**Mitigation:** Support environment variable override:
```bash
export AGENTMON_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

#### MEDIUM: ReDoS in Syslog Parser

**Location:** `agentmon/collectors/syslog_receiver.py:27-46`

**Risk:** Crafted syslog messages could cause catastrophic regex backtracking, consuming CPU.

**Mitigation:**
- Add message length limits before regex matching
- Use more specific character classes instead of `\S+`
- Test regexes with ReDoS detection tools

#### MEDIUM: Database Path Traversal

**Location:** `agentmon/config.py:110`

**Risk:** Malicious config could write database to arbitrary locations (web roots, system directories).

**Mitigation:** Validate paths against an allowlist of directories:
```python
ALLOWED_DB_DIRS = [
    Path.home() / ".local" / "share" / "agentmon",
    Path("/var/lib/agentmon"),
]
```

#### MEDIUM: No Validation on Known-Bad Patterns

**Location:** `agentmon/analyzers/dns_baseline.py:286`

**Risk:** Empty string or single-character patterns match all/most domains, causing alert floods.

**Mitigation:** Reject patterns shorter than 2-3 characters.

#### MEDIUM: Missing TLS for Syslog

**Location:** `agentmon/collectors/syslog_receiver.py`

**Risk:** Syslog messages transmitted in plaintext can be eavesdropped or modified.

**Mitigation:**
- Use VPN/WireGuard between devices (recommended)
- Implement RFC 5425 TLS syslog (future enhancement)

#### LOW: No Rate Limiting on Syslog

**Location:** `agentmon/collectors/syslog_receiver.py`

**Risk:** Flood of messages can exhaust CPU, memory, or disk.

**Mitigation:** Implement per-IP token bucket rate limiting.

#### LOW: Paramiko AutoAddPolicy

**Location:** `agentmon/collectors/pihole.py:96`

**Risk:** SSH client trusts unknown host keys, enabling MITM attacks.

**Mitigation:** Use `RejectPolicy` and require hosts in `~/.ssh/known_hosts`.

#### LOW: No Config File Integrity Check

**Location:** `agentmon/config.py`

**Risk:** Config modifications go undetected.

**Mitigation:** Optional SHA256 checksum verification via `.toml.sha256` sidecar file.

## Deployment Hardening

### Syslog Receiver

```bash
# Bind to specific interface, not all (0.0.0.0)
agentmon listen --bind 192.168.1.100

# Always use IP allowlist for remote access
agentmon listen --bind 192.168.1.100 --allow 192.168.1.2 --allow 192.168.1.3
```

### File Permissions

```bash
# Restrict config file (contains webhook URLs)
chmod 600 ~/.config/agentmon/agentmon.toml

# Restrict database (contains DNS query history)
chmod 600 ~/.local/share/agentmon/events.db
```

### Secrets Management

Prefer environment variables over config file for sensitive values:

```bash
# Slack webhook
export AGENTMON_SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# Then in config, leave webhook_url commented out
```

### Network Isolation

For production deployments:

1. **Same-host deployment:** Run agentmon on the same machine as Pi-hole (localhost syslog)
2. **VPN/WireGuard:** Encrypt syslog traffic between devices
3. **Firewall rules:** Restrict syslog port to specific source IPs

### Container Isolation

```bash
# Run as unprivileged user
docker run --user 1000:1000 ...

# Read-only filesystem where possible
docker run --read-only --tmpfs /tmp ...

# Drop all capabilities
docker run --cap-drop=ALL ...
```

## Reporting Security Issues

If you discover a security vulnerability, please report it privately rather than opening a public issue.

Contact: [Add security contact email or process]

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Design Decisions

### Why localhost-only by default?

Binding to `127.0.0.1` by default prevents accidental network exposure. Users must explicitly opt-in to remote access with `--bind`, making the security implications clear.

### Why no authentication on syslog?

Standard syslog (RFC 3164/5424) has no authentication. We rely on:
- Network-level controls (bind address, IP allowlist, firewall)
- Transport-level encryption (VPN/TLS)

Adding application-level auth would require non-standard syslog clients.

### Why sanitize LLM inputs?

Domain names come from untrusted network traffic. Without sanitization, attackers could craft DNS queries containing prompt injection attacks, potentially causing the LLM to misclassify malicious domains as benign.

### Why not encrypt the database?

DuckDB doesn't support encryption natively. For sensitive deployments:
- Use filesystem-level encryption (LUKS, FileVault, BitLocker)
- Restrict file permissions
- Consider full-disk encryption

### Device Activity Baseline Privacy

The `device_activity_baseline` table stores per-device, per-hour activity patterns:
- Which devices are active at which hours
- Historical activity ratios (how often each device is active per time slot)

This data could reveal:
- Sleep schedules (when devices go inactive)
- Work patterns (regular activity hours)
- Travel/absence (prolonged inactivity)

**Mitigations:**
- Same database file permissions (chmod 600) protect this data
- Data is aggregated (counts, not individual queries)
- Consider shorter `learning_days` if privacy is a concern
- Mark devices as `always_active = true` to exclude from tracking
