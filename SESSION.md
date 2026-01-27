# agentmon Session State

**Last updated:** 2026-01-26

## Project Overview

Building a network agent activity monitor to detect malicious agent behavior by auditing:
- DNS queries (Pi-hole)
- Network connections (OpenWRT)
- Process-to-socket mapping (host agents)

## Infrastructure

| Component | Hardware | Role |
|-----------|----------|------|
| Pi-hole | Raspberry Pi 2 | DNS logging (`/var/log/pihole/pihole.log`) |
| OpenWRT | Raspberry Pi 4 CM | Connection tracking (Phase 2) |
| LLM Server | 2x 3090, ample RAM | Analysis hub, runs agentmon |

**LLM capabilities:**
- Local: Llama 3.3 70B, gpt-120b OSS
- Escalation: Frontier APIs available

**Target hosts (Phase 3):** macOS, Windows + WSL2, IoT (passive)

## Current Implementation Status

### Completed (Phase 1 - Partial)

- [x] Project structure scaffolded
- [x] Data models (`DNSEvent`, `ConnectionEvent`, `ProcessNetworkEvent`, `Alert`)
- [x] Pi-hole FTL database collector (`collectors/pihole.py`)
- [x] Pi-hole log file collector (`collectors/pihole_log.py`)
- [x] DuckDB storage layer (`storage/db.py`)
- [x] Entropy/DGA detection (`analyzers/entropy.py`) - 14 tests passing
- [x] DNS baseline analyzer (`analyzers/dns_baseline.py`)
- [x] LLM classifier stub (`llm/classifier.py`)
- [x] CLI with commands: `collect`, `alerts`, `stats`, `baseline`
- [x] Example config file

### Not Yet Implemented

- [ ] Config file loading (currently CLI-only)
- [ ] Scheduled collection (cron/systemd)
- [ ] Real-time log streaming mode
- [ ] LLM integration wiring (endpoint configuration)
- [ ] Known-bad domain lists / threat intel feeds
- [ ] Alerting outputs (webhook, ntfy, email)

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

# Collect from Pi-hole (once SSH is configured)
agentmon collect --host <pihole-ip> --learning
```

## Key Files

| File | Purpose |
|------|---------|
| `agentmon/collectors/pihole.py` | FTL database collector |
| `agentmon/collectors/pihole_log.py` | Log file collector |
| `agentmon/analyzers/entropy.py` | DGA/entropy detection |
| `agentmon/analyzers/dns_baseline.py` | Baseline anomaly detection |
| `agentmon/storage/db.py` | DuckDB storage |
| `agentmon/llm/classifier.py` | LLM domain classification |
| `agentmon/cli.py` | CLI entry point |
| `config/agentmon.example.toml` | Example configuration |

## Next Steps (Suggested)

1. **Verify Pi-hole setup** - Confirm FTL.db path or use log collector
2. **Configure SSH** - Set up passwordless SSH to Pi-hole
3. **Run learning mode** - Build initial baseline
4. **Wire LLM** - Connect to local Llama 3.3 endpoint
5. **Add scheduling** - Cron or systemd timer for periodic collection

## Design Decisions

- **Python first** - Rapid iteration, potential Rust rewrite later
- **DuckDB** - Analytical queries, single-file, column-oriented
- **Tiered LLM** - Rules → Local 70B → Frontier API escalation
- **Pull model** - Hub pulls from edge devices (keeps Pi lightweight)
- **Strict typing** - Full type hints for Rust migration path
