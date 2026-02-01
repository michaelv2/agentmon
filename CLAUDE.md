# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agentmon is a network agent activity monitor and auditor that detects anomalous DNS activity from AI agents and other software by monitoring Pi-hole and/or OpenWRT logs. It uses DuckDB for storage, supports LLM-based domain classification via Ollama, integrates threat intelligence feeds, and provides real-time alerting through Slack.

## Commands

### Development Setup

```bash
# Create virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_syslog.py

# Run tests with verbose output
pytest -v

# Run tests with coverage
pytest --cov=agentmon
```

### Linting and Type Checking

```bash
# Run type checker
mypy agentmon/

# Run linter (configured in pyproject.toml)
ruff check agentmon/

# Auto-fix linting issues
ruff check --fix agentmon/
```

### Running the Application

```bash
# Start syslog receiver (push model)
agentmon listen --port 1514

# Start with LLM classification
agentmon listen --port 1514 --llm

# Learning mode (build baseline without alerts)
agentmon listen --port 1514 --learning

# Poll Pi-hole database (pull model)
agentmon collect --local /path/to/pihole-FTL.db
agentmon collect --host pihole.local --user pi

# View statistics and alerts
agentmon stats --hours 24
agentmon alerts --severity medium
agentmon baseline
agentmon feeds

# Data cleanup
agentmon cleanup --dns-days 7 --alerts-days 30 --vacuum
```

## Architecture

### Core Components

**Data Flow:**
```
Pi-hole/OpenWRT → Syslog → SyslogReceiver → Parsers → Analyzers → EventStore (DuckDB)
                                                    ↓
                                              Notifiers (Slack)
```

**Key Modules:**

- **`agentmon/models/`**: Core data models (DNSEvent, Alert, Severity)
  - Uses frozen dataclasses with slots for potential Rust migration
  - All models are in `events.py`

- **`agentmon/storage/`**: DuckDB-backed event store
  - `db.py`: EventStore class with schema management
  - Column-oriented storage optimized for time-series analytics
  - Schema versioning system for migrations

- **`agentmon/collectors/`**: Log collection from edge devices
  - `syslog_receiver.py`: TCP/UDP syslog server
  - `syslog_parsers.py`: Message routing and parsing logic
  - `pihole.py`: Direct Pi-hole database collector (pull model)

- **`agentmon/analyzers/`**: Threat detection engines
  - `dns_baseline.py`: DNSBaselineAnalyzer - learns per-client domain patterns, detects new/suspicious domains
  - `entropy.py`: DGA detection using Shannon entropy
  - `device_activity.py`: DeviceActivityAnalyzer - learns device activity patterns, detects off-hours anomalies

- **`agentmon/llm/`**: LLM-based domain classification
  - `classifier.py`: Two-tier Ollama integration (fast triage → thorough escalation)
  - Supports VirusTotal integration for threat intelligence

- **`agentmon/threat_intel/`**: External threat intelligence
  - `virustotal.py`: VirusTotal API client with caching

- **`agentmon/threat_feeds.py`**: Threat feed management (URLhaus, Feodo Tracker)

- **`agentmon/notifiers/`**: Alert notification systems
  - `slack.py`: Slack webhook integration

- **`agentmon/policies/`**: Policy enforcement
  - Parental control analyzer with time-based content filtering

- **`agentmon/resolver.py`**: Client IP → hostname resolution
  - Resolves IPs to stable hostnames so baselines survive DHCP changes
  - Uses PTR lookups with explicit mapping fallbacks

- **`agentmon/config.py`**: TOML configuration loading
  - Searches: `./agentmon.toml`, `~/.config/agentmon/agentmon.toml`, `/etc/agentmon/agentmon.toml`

- **`agentmon/cli.py`**: Click-based CLI interface
  - All commands route through here
  - Uses Rich for terminal output formatting

### Database Schema

**Tables:**
- `dns_events`: Raw DNS query events (retention-managed)
- `alerts`: Generated security/policy alerts (retention-managed)
- `domain_baseline`: Per-client domain baselines (indefinite, bounded by design)
- `device_activity_baseline`: Per-client activity hour baselines (indefinite, bounded: 168 rows/device max)

**Retention Model:**
- Raw events and alerts are cleaned up based on `[retention]` config
- Baselines are kept indefinitely (they're bounded: domain_baseline by unique client-domain pairs, device_activity_baseline by 168 time slots per client)

### Two-Tier Analysis Architecture

The analyzer system uses a layered approach:

1. **Baseline Learning**: DNSBaselineAnalyzer tracks first-seen domains per client
2. **Pattern Matching**: Entropy analysis (DGA detection), known-bad patterns
3. **Threat Feeds**: URLhaus and Feodo Tracker integration
4. **LLM Classification** (optional):
   - Fast triage model (phi3:3.8b) for initial classification
   - Escalation to thorough model (gpt-oss:20b) for suspicious domains
   - VirusTotal integration for additional context before escalation
   - Triage model auto-unloads after use (keep_alive + HTTP API) to free GPU/RAM

### Client Identity Resolution

**Problem**: DHCP reassignment breaks per-client baseline learning.

**Solution**: ClientResolver maps IPs to stable hostnames:
1. Explicit config mappings (highest priority)
2. Reverse DNS (PTR) lookups
3. Raw IP fallback

When enabled (`[client_resolver] enabled = true`), all baseline tracking uses hostnames instead of IPs.

**Migration**: Enabling resolver makes existing IP-based baselines stale. Clear and re-learn:
```bash
duckdb ~/.local/share/agentmon/events.db "DELETE FROM domain_baseline"
```

### Device Activity Anomaly Detection

Learns each device's normal activity hours and alerts on deviations without hard-coded rules.

**How it works:**
1. **Learning phase** (default: 14 days): Track query counts per device per hour-of-week slot
2. **Detection phase**: Alert when device is active in a time slot where it's historically inactive (<10% of observations)
3. **Baseline storage**: `device_activity_baseline` table (max 168 rows per device: 7 days × 24 hours)

**Configuration**: `[device_activity]` section in config, see `config/agentmon.example.toml`

## Configuration

Configuration uses TOML format. See `config/agentmon.example.toml` for comprehensive examples.

**Search order**: `./agentmon.toml` → `~/.config/agentmon/agentmon.toml` → `/etc/agentmon/agentmon.toml`

**Key sections:**
- `[analyzer]`: Entropy thresholds, known-bad patterns, allowlists
- `[llm]`: Ollama models, escalation settings
- `[threat_feeds]`: URLhaus/Feodo integration
- `[virustotal]`: API key (prefer env var: `AGENTMON_VIRUSTOTAL_API_KEY`)
- `[client_resolver]`: IP → hostname resolution
- `[device_activity]`: Activity anomaly detection
- `[retention]`: Data cleanup policies
- `[slack]`: Webhook notifications
- `[syslog]`: Receiver settings

## Code Style

- **Python version**: 3.11+ (uses modern type hints)
- **Type checking**: mypy strict mode enabled
- **Linting**: ruff with select rules (E, F, I, N, W, UP, ANN, B, C4, SIM)
- **Line length**: 100 characters
- **Data models**: Frozen dataclasses with slots (enables potential Rust migration)
- **Logging**: Use stdlib `logging` module, not print statements
- **CLI output**: Use Rich library for formatted terminal output

## Important Implementation Notes

### DuckDB Usage

- Use DuckDB SQL (not pandas/SQLAlchemy)
- Prefer batch inserts for performance: `insert_dns_events_batch()`
- Use context manager or explicit `connect()`/`close()` for connection lifecycle
- Read-only connections copy to temp file to avoid lock conflicts

### LLM Integration

- Two-tier classification to minimize cost/latency
- Triage model runs on all suspicious domains
- Escalation model only runs when triage confidence < threshold or category matches escalation list
- VirusTotal lookup happens between triage and escalation
- Results cached with TTL to avoid redundant API calls
- Triage model is unloaded after use via `keep_alive=1` and HTTP API (`/api/generate` with `keep_alive=0`) to free GPU/RAM; uses `requests` library for the HTTP call

### Alert Deduplication

- DNSBaselineAnalyzer maintains in-memory TTL cache of recent alerts
- Default: 10 minutes deduplication window, 5000 alert cache size
- Prevents alert spam for repeated queries to same domain

### Syslog Message Handling

- Pi-hole sends block notifications as separate messages (not inline with query)
- Parser correlates block notifications with recent queries via `mark_domain_blocked()`
- Client resolution happens before analysis to ensure baselines use hostnames

### Schema Migrations

- `SCHEMA_VERSION` constant in `agentmon/storage/db.py`
- Migration logic in `_migrate_schema()` method
- Increment version when adding/modifying tables

### Testing Strategy

- Unit tests in `tests/` directory
- Test files mirror source structure: `test_syslog.py`, `test_entropy.py`
- Use pytest with asyncio support for async tests
- Mock external dependencies (Ollama, VirusTotal, network calls)

## Security Considerations

- Default syslog listener binds to 127.0.0.1 (localhost only)
- Use `--bind` and `--allow` flags to accept remote connections securely
- VirusTotal API key should use env var (`AGENTMON_VIRUSTOTAL_API_KEY`), not config file
- No sensitive data in logs (IP addresses logged at INFO level only in verbose mode)
- See `SECURITY.md` for full threat model and hardening recommendations
