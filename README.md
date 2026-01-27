# agentmon

Network agent activity monitor and auditor.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Collect from local Pi-hole database
agentmon collect --local /etc/pihole/pihole-FTL.db

# Collect from remote Pi-hole via SSH
agentmon collect --host pihole.local --user pi

# Learning mode (build baseline without alerting)
agentmon collect --host pihole.local --learning

# Show alerts
agentmon alerts

# Show statistics
agentmon stats
```
