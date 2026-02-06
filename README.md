# agentmon

Network agent activity monitor and auditor. Detects anomalous DNS activity from AI agents and other software by monitoring Pi-hole and/or OpenWRT logs.

This project grew out of a desire to better understand what AI agents (e.g., Clawdbot / Moltbot, Auto-GPT, BabyAGI) are doing on a network. By monitoring DNS and router activity, we can detect potentially unwanted or suspicious behavior, such as connections to known command-and-control servers, domain generation algorithms (DGAs), or other anomalous patterns.

The simplest configuration is to run a Pi-hole instance on the network and have agentmon monitor its logs. For more advanced setups, OpenWRT integration can provide additional context via connection tracking and firewall logs.

The LLM integration allows for intelligent classification of domains based on their context and behavior, enabling more nuanced detection of potential threats. It requires an Ollama instance running locally or remotely, but is optional.

## Features

- **Baseline learning** - Builds per-client domain baseline, alerts on new/unusual domains
- **DGA detection** - Flags algorithmically-generated domains using entropy analysis
- **Known-bad patterns** - Matches against configurable threat indicators (C2, malware, mining pools)
- **Threat intelligence feeds** - Automatic updates from URLhaus, Feodo Tracker (malware/C2/phishing)
- **LLM classification** - Two-tier Ollama integration for intelligent domain analysis
- **Device activity anomaly** - Learns normal activity hours per device, alerts on off-hours activity
- **Parental controls** - Time-based content filtering with category blocking
- **Data retention** - Automatic cleanup of old events with configurable retention periods
- **Slack alerts** - Real-time webhook notifications with severity filtering
- **Syslog receiver** - Push-based collection from edge devices (no credentials on hub)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

### 1. Start the syslog receiver

```bash
# Learning mode - build baseline of normal domains (run for 1-2 days)
agentmon listen --port 1514 --learning

# Detection mode - alert on new/suspicious domains
agentmon listen --port 1514

# With LLM classification (requires Ollama running locally)
agentmon listen --port 1514 --llm
```

### 2. Configure Pi-hole to forward logs

On the Pi-hole device, create a systemd service:

```bash
sudo tee /etc/systemd/system/agentmon-forward.service << 'EOF'
[Unit]
Description=Forward Pi-hole logs to agentmon
After=network.target pihole-FTL.service

[Service]
Type=simple
ExecStart=/bin/sh -c 'tail -F /var/log/pihole/pihole.log | logger -t pihole -n <hub-ip> -P 1514 --tcp'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now agentmon-forward
```

See [docs/edge-setup.md](docs/edge-setup.md) for detailed configuration options.

### 3. View results

```bash
# Show DNS statistics per client
agentmon stats

# Show unacknowledged alerts
agentmon alerts

# Show baseline statistics
agentmon baseline
```

## Configuration

Copy the example config and customize:

```bash
mkdir -p ~/.config/agentmon
cp config/agentmon.example.toml ~/.config/agentmon/agentmon.toml
```

Config is searched in order: `./agentmon.toml`, `~/.config/agentmon/agentmon.toml`, `/etc/agentmon/agentmon.toml`

### Analyzer settings

```toml
[analyzer]
# Entropy threshold for DGA detection (higher = fewer false positives)
entropy_threshold = 3.5
entropy_min_length = 10

# Learning mode: only build baseline, don't generate alerts
learning_mode = false

# Known-bad domain patterns (substring match, case-insensitive)
known_bad_patterns = [
    "c2-", "beacon", "malware", "botnet", "ransomware",
    "stratum", "xmr-pool", "mining-pool",
]

# Domains to always ignore (exact match)
allowlist = [
    "localhost",
]

# Domain suffixes to ignore (covers all subdomains)
ignore_suffixes = [
    ".local", ".lan", ".home", ".internal", ".arpa",
    ".slack.com",  # Example: whitelist all Slack domains
]
```

### LLM classification

Requires [Ollama](https://ollama.ai) running locally or on a remote host.

```toml
[llm]
enabled = false

# Two-tier classification: fast triage, thorough escalation
triage_model = "phi3:3.8b"
escalation_model = "gpt-oss:20b"

# Escalate when triage returns these categories
escalation_categories = ["suspicious", "likely_malicious", "dga", "unknown"]

# Also escalate when triage confidence is below this threshold
escalation_confidence_threshold = 0.7
```

Enable at runtime with `--llm` flag:

```bash
agentmon listen --llm

# For remote Ollama server, set OLLAMA_HOST before running:
export OLLAMA_HOST="your_ollama_host:11434"
agentmon listen --llm
```

### Threat intelligence feeds

Automatically downloads and checks domains against external threat feeds from reputable sources (URLhaus, Feodo Tracker). Provides high-confidence alerts for known malware/C2/phishing domains.

```toml
[threat_feeds]
enabled = true

# Directory to cache downloaded feeds
cache_dir = "~/.cache/agentmon/feeds"

# How often to refresh feeds (hours)
update_interval_hours = 24

# Alert severity for threat feed matches
alert_severity = "high"
```

Manual feed management:

```bash
# Update feeds and show statistics
agentmon feeds

# Feeds are automatically updated when stale during startup
```

**Feed sources:**
- **URLhaus (abuse.ch)** - Malware distribution sites, C2 servers, phishing
- **Feodo Tracker (abuse.ch)** - Banking trojan C2 servers (Dridex, TrickBot, Emotet)

### VirusTotal reputation checking

Real-time vendor detection counts from VirusTotal. When LLM classification encounters a domain, it queries VirusTotal for current reputation (malicious detections, vendor consensus). Provides the latest threat intelligence to inform model decisions.

Get a free VirusTotal API key at: https://www.virustotal.com/gui/my-apikey

```bash
# Set API key via environment variable (recommended)
export AGENTMON_VIRUSTOTAL_API_KEY="your-api-key-here"
agentmon listen --port 1514 --llm
```

Or configure in `agentmon.toml`:

```toml
[virustotal]
# API key - SECURITY: Prefer environment variable (AGENTMON_VIRUSTOTAL_API_KEY)
# api_key = "YOUR_API_KEY_HERE"

# Cache VirusTotal results for 24 hours
cache_ttl = 86400
```

**How it works:**
1. LLM triage model classifies domain as suspicious/unknown
2. Before escalating to larger model, query VirusTotal
3. Include vendor detection summary in prompt: "VirusTotal: 12 malicious, 5 suspicious (21 vendors)"
4. Larger model uses this context for final decision
5. Results cached for 24 hours to respect rate limits

**Free tier limits:** 4 requests/min, 500/day - suitable for small to medium networks

### Client identity resolution

Resolves client IPs to stable hostnames so baselines survive DHCP changes.

```toml
[client_resolver]
enabled = true
cache_ttl = 3600  # 1 hour
strip_suffix = true  # "alice-laptop.lan" → "alice-laptop"

# Explicit mappings for devices without PTR records
[[client_resolver.mappings]]
ip = "192.168.1.100"
name = "media-server"
```

### Device activity anomaly detection

Learns each device's normal activity hours and alerts when activity occurs outside those patterns. No hard-coded time rules required - the system learns from observed behavior.

```toml
[device_activity]
enabled = true

# Learning period before generating alerts (days)
learning_days = 14

# Minimum queries in an hour to consider device "active"
activity_threshold = 5

# Alert severity for activity anomalies
alert_severity = "medium"

# Named devices for better alert messages
[[device_activity.devices]]
name = "alice-laptop"
client_ips = ["192.168.1.50"]

[[device_activity.devices]]
name = "media-server"
client_ips = ["192.168.1.100"]
always_active = true  # Skip anomaly detection for 24/7 devices
```

**Example:** If `alice-laptop` is normally active from 7am-10pm and suddenly starts querying DNS at 3:15 AM, an alert is generated: "Unusual activity: alice-laptop active at 03:00".

### Data retention

Automatically cleans up old data to manage disk usage. Baselines are not affected (they're bounded by design).

```toml
[retention]
enabled = true

# Keep raw DNS events for 30 days
dns_events_days = 30

# Keep alerts for 90 days
alerts_days = 90

# Run cleanup at startup and every 24 hours
cleanup_interval_hours = 24
```

Manual cleanup: `agentmon cleanup --dns-days 7 --alerts-days 30 --vacuum`

### Slack notifications

```toml
[slack]
enabled = true

# Webhook URL from Slack App configuration
# Create at: https://api.slack.com/apps -> Incoming Webhooks
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"

# Minimum severity to notify (info, low, medium, high, critical)
min_severity = "medium"
```

## Alternative: Pull Model (SSH)

For environments where syslog forwarding isn't practical:

```bash
# Collect from local Pi-hole database
agentmon collect --local /etc/pihole/pihole-FTL.db

# Collect from remote Pi-hole via SSH
agentmon collect --host pihole.local --user pi

# Learning mode (build baseline without alerting)
agentmon collect --host pihole.local --learning
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `agentmon listen` | Start syslog receiver (push model) |
| `agentmon collect` | Poll Pi-hole database (pull model) |
| `agentmon stats` | Show DNS query statistics per client |
| `agentmon alerts` | Show unacknowledged security alerts |
| `agentmon baseline` | Show learned baseline statistics |
| `agentmon cleanup` | Clean up old data per retention policy |
| `agentmon feeds` | Update and show threat intelligence feed status |

### Listen options

| Flag | Description |
|------|-------------|
| `--port` | Syslog port (default: 1514) |
| `--protocol` | tcp, udp, or both (default: tcp) |
| `--bind` | Bind address (default: 127.0.0.1) |
| `--allow` | IP allowlist (can specify multiple times) |
| `--learning` | Learning mode - build baseline only |
| `--llm` | Enable LLM classification |

**Security note:** By default, agentmon only listens on localhost. To receive logs from remote devices, specify `--bind` with your LAN IP and use `--allow` to restrict source IPs:

```bash
agentmon listen --bind 192.168.1.100 --allow 192.168.1.2 --allow 192.168.1.3
```

## Architecture

```
┌─────────────┐  syslog/TCP   ┌─────────────┐     ┌─────────┐
│   Pi-hole   │ ────────────> │   agentmon  │ ──> │  Slack  │
│  (dnsmasq)  │    :1514      │    (hub)    │     └─────────┘
└─────────────┘               └──────┬──────┘
                                     │
                              ┌──────┴──────┐
                              │   DuckDB    │
                              │  events.db  │
                              └─────────────┘
                                     │
                              ┌──────┴──────┐
                              │   Ollama    │
                              │  (optional) │
                              └─────────────┘
```

## Alert Severities

| Severity | Triggers |
|----------|----------|
| CRITICAL | Reserved for confirmed threats |
| HIGH | Known-bad pattern match (C2, malware, etc.), parental control violations |
| MEDIUM | DGA-like domain detected, device activity anomaly (off-hours) |
| LOW | New domain from client (not in baseline) |
| INFO | Informational observations |

## Security

See [SECURITY.md](SECURITY.md) for:
- Threat model and attack surface
- Known security issues and mitigations
- Deployment hardening recommendations
- How to report vulnerabilities

## Production Deployment

### systemd service

agentmon ships with a systemd unit file for running as a daemon.

```bash
# 1. Create a dedicated user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin agentmon

# 2. Create data and config directories
sudo mkdir -p /var/lib/agentmon
sudo chown agentmon:agentmon /var/lib/agentmon
sudo mkdir -p /etc/agentmon

# 3. Copy config (edit to taste)
sudo cp config/agentmon.example.toml /etc/agentmon/agentmon.toml

# 4. Create environment file for secrets
sudo tee /etc/agentmon/environment << 'EOF'
# Uncomment and set as needed:
# AGENTMON_VIRUSTOTAL_API_KEY=your-key-here
# OLLAMA_HOST=http://localhost:11434
EOF
sudo chmod 600 /etc/agentmon/environment

# 5. Install the service
sudo cp config/agentmon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agentmon
```

### Service management

```bash
sudo systemctl status agentmon     # Check status
sudo journalctl -u agentmon -f     # Follow logs
sudo systemctl restart agentmon    # Restart after config changes
```

The service runs with security hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`) and stores its DuckDB database in `/var/lib/agentmon/`. Config is auto-discovered from `/etc/agentmon/agentmon.toml`.

## Architecture Details

See [SMART_ANALYZE.md](docs/SMART_ANALYZE.md) for technical details on:
- Client identity resolution implementation
- Device activity anomaly detection algorithm
- Data retention policy design
