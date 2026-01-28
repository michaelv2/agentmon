# agentmon

Network agent activity monitor and auditor. Detects anomalous DNS activity from AI agents and other software by monitoring Pi-hole logs.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start (Syslog Push Model)

The recommended setup uses syslog forwarding from edge devices to agentmon. This is more secure than SSH-based polling since the hub holds no credentials to network infrastructure.

### 1. Start the syslog receiver

```bash
# Learning mode - build baseline of normal domains (run for 1-2 days)
agentmon listen --port 1514 --learning

# Detection mode - alert on new/suspicious domains
agentmon listen --port 1514
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

## Architecture

```
┌─────────────┐  syslog/TCP   ┌─────────────┐
│   Pi-hole   │ ────────────> │   agentmon  │
│  (dnsmasq)  │    :1514      │    (hub)    │
└─────────────┘               └─────────────┘
                                    │
                              ┌─────┴─────┐
                              │  DuckDB   │
                              │ events.db │
                              └───────────┘
```
