# agentmon Session State

**Last updated:** 2026-01-28

## Project Overview

Network agent activity monitor that detects anomalous DNS activity from AI agents and other software by monitoring Pi-hole logs. Uses baseline learning, entropy analysis, pattern matching, and optional LLM classification.

## Infrastructure

| Component | Hardware | Role |
|-----------|----------|------|
| Pi-hole | Raspberry Pi 2 | DNS logging, forwards via syslog |
| OpenWRT | Raspberry Pi 4 CM | Connection tracking (Phase 2) |
| LLM Server | 2x 3090, ample RAM | Analysis hub, runs agentmon + Ollama |

**LLM capabilities:**
- Triage: phi3:3.8b (fast, local)
- Escalation: gpt-oss:20b (thorough, local)
- Frontier APIs available for further escalation

## Current Implementation Status

### Completed

- [x] Project structure with full test suite (40 tests)
- [x] Data models (`DNSEvent`, `ConnectionEvent`, `Alert`, `Severity`)
- [x] Pi-hole collectors (FTL database, log file, syslog receiver)
- [x] DuckDB storage layer with baseline tables
- [x] Entropy/DGA detection with configurable thresholds
- [x] DNS baseline analyzer with known-bad pattern matching
- [x] Two-tier LLM classification (triage → escalation)
- [x] Parental controls with time-based policies and category blocking
- [x] Device activity anomaly detection (learns normal hours, alerts on deviations)
- [x] Client identity resolution (IP → hostname via reverse DNS)
- [x] Data retention policy with automatic cleanup
- [x] Slack webhook notifications with severity filtering
- [x] Config file loading (TOML) with CLI override support
- [x] CLI commands: `listen`, `collect`, `alerts`, `stats`, `baseline`, `cleanup`

### Phase 2 (OpenWRT) - Not Started

- [ ] OpenWRT conntrack collector
- [ ] Firewall log collector
- [ ] Connection-to-DNS correlation
- [ ] Direct IP access detection

### Phase 3 (Host Agents) - Not Started

- [ ] macOS agent (lsof/nettop)
- [ ] Windows agent (Get-NetTCPConnection, ETW)
- [ ] WSL2 considerations
- [ ] Authority model / grants config

### Phase 4 (Correlation) - Not Started

- [ ] Cross-source correlation engine
- [ ] Timeline reconstruction
- [ ] Beaconing detection

## How to Resume

```bash
cd /home/maqo/projects/agentmon
source .venv/bin/activate

# Run tests
pytest tests/ -v

# Test CLI
agentmon --help

# Start syslog receiver (push model - recommended)
agentmon listen --port 1514

# Or collect from Pi-hole database (pull model)
agentmon collect --host <pihole-ip> --learning

# View data
agentmon stats
agentmon alerts
agentmon baseline

# Manual cleanup
agentmon cleanup --dry-run
```

## Key Files

| File | Purpose |
|------|---------|
| `agentmon/cli.py` | CLI entry point with all commands |
| `agentmon/config.py` | TOML config loading |
| `agentmon/storage/db.py` | DuckDB storage + cleanup methods |
| `agentmon/analyzers/dns_baseline.py` | Security analysis + LLM integration |
| `agentmon/analyzers/device_activity.py` | Activity anomaly detection |
| `agentmon/analyzers/entropy.py` | DGA/entropy detection |
| `agentmon/resolver.py` | Client IP → hostname resolution |
| `agentmon/policies/` | Parental controls framework |
| `agentmon/notifiers/slack.py` | Slack webhook notifications |
| `agentmon/collectors/syslog_receiver.py` | Syslog server for push model |
| `config/agentmon.example.toml` | Full configuration reference |

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | User-facing documentation |
| `SECURITY.md` | Threat model and hardening guide |
| `SMART_ANALYZE.md` | Smart analysis features (all implemented) |
| `IDEAS.md` | Future improvement ideas |
| `docs/edge-setup.md` | Pi-hole forwarding configuration |

## Configuration Highlights

```toml
# Key sections in agentmon.toml:
[syslog]           # Receiver settings (port, bind, allowed IPs)
[analyzer]         # Entropy thresholds, known-bad patterns, allowlist
[llm]              # Two-tier classification (triage + escalation models)
[slack]            # Webhook notifications
[parental_controls] # Time-based content filtering
[device_activity]  # Activity anomaly detection
[client_resolver]  # IP → hostname resolution
[retention]        # Automatic data cleanup
```

## Design Decisions

- **Push model preferred** - Syslog forwarding from edge (no credentials on hub)
- **Python first** - Rapid iteration, potential Rust rewrite later
- **DuckDB** - Analytical queries, single-file, column-oriented
- **Tiered LLM** - Fast triage → thorough escalation → frontier API
- **Strict typing** - Full type hints for Rust migration path
- **Bounded baselines** - Domain/activity baselines don't grow unbounded
