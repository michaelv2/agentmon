# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

agentmon is a network agent activity monitor and auditor that detects anomalous DNS activity from AI agents and other software by monitoring Pi-hole and/or OpenWRT logs. It uses DuckDB for storage, supports LLM-based domain classification via Ollama, integrates threat intelligence feeds, and provides real-time alerting through Slack.

## System Context

agentmon is one component of a tightly coupled home network security stack. Changes to any component can affect the others — always consider the system holistically.

```
┌─────────────────────────────────────────────────────┐
│                    Network Stack                     │
│                                                      │
│  ┌────────────┐  DNS queries   ┌────────────┐       │
│  │  Clients   │ ─────────────> │  Pi-hole    │       │
│  │ (70-80     │  (forced via   │  (DNS +     │       │
│  │  devices)  │   DNAT rule)   │  blocklist) │       │
│  └────────────┘                └─────┬──────┘       │
│                                      │ syslog/TCP   │
│  ┌────────────┐  firewall     ┌──────▼──────┐       │
│  │  pi-route  │  logs via     │  agentmon   │       │
│  │  (OpenWRT  │ ────────────> │  (monitor + │       │
│  │   router)  │  syslog       │   alerting) │       │
│  └────────────┘               └─────────────┘       │
└─────────────────────────────────────────────────────┘
```

**Components and repos:**

| Component | Repo | Role |
|-----------|------|------|
| **pi-route** | `~/projects/pi-route` | OpenWRT router (CM4). DNS DNAT to Pi-hole, DoH/DoT blocking, firewall, parental controls |
| **Pi-hole** | *(no repo — config-managed)* | DNS resolver + blocklist. Runs Pi-hole v6 (FTL). Configured via web UI and `pihole-FTL --config` |
| **agentmon** | `~/projects/agentmon` | Monitoring layer. Receives syslog from Pi-hole and OpenWRT, analyzes DNS patterns, alerts |

**Key dependencies and coupling:**
- agentmon's visibility depends on Pi-hole seeing all DNS → pi-route must force DNS to Pi-hole (DNAT) and block DoH/DoT
- agentmon's syslog parser expects Pi-hole's dnsmasq log format → Pi-hole version changes can break parsing
- pi-route's firewall logs flow to agentmon → firewall rule changes affect what agentmon sees
- Pi-hole's conditional forwarding interacts with pi-route's DNS → misconfiguration causes loops (see Troubleshooting in `docs/edge-setup.md`)
- Client resolver maps IPs to hostnames using Pi-hole's DHCP/DNS data → Pi-hole or router DHCP changes affect baseline continuity
- Pi-hole v6 uses `pihole-FTL --config` for all configuration; `/etc/dnsmasq.d/` is NOT read by FTL

**When making changes, consider:**
- DNS rule changes on pi-route → does agentmon still see all queries?
- Pi-hole config changes → does syslog forwarding still work? Do parsers handle the format?
- agentmon analyzer changes → do thresholds make sense given the network's traffic patterns (~70-80 devices)?

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
  - `dns_baseline.py`: DNSBaselineAnalyzer - learns per-client domain patterns, detects new/suspicious domains, OCSP spike detection
  - `entropy.py`: DGA detection using Shannon entropy, trusted infrastructure modifier for CDN/cloud parents
  - `device_activity.py`: DeviceActivityAnalyzer - learns device activity patterns, detects off-hours anomalies

- **`agentmon/llm/`**: LLM-based domain classification
  - `classifier.py`: Two-tier Ollama integration (fast triage → thorough escalation)
  - Supports VirusTotal integration for threat intelligence

- **`agentmon/threat_intel/`**: External threat intelligence
  - `virustotal.py`: VirusTotal API client with caching

- **`agentmon/threat_feeds.py`**: Threat feed management (URLhaus, CERT.PL)

- **`agentmon/notifiers/`**: Alert notification systems
  - `slack.py`: Slack webhook integration

- **`agentmon/watchdog/`**: OODA Watchdog — periodic LLM-based traffic evaluation
  - `ooda.py`: OODAWatchdog class — runs Observe-Orient-Decide-Act cycles on a timer
  - `models.py`: OODASnapshot, OODAConcern, WatchdogReport, SelfAwarenessMetrics
  - `queries.py`: DuckDB queries for traffic snapshots (top domains, top clients, new domains, recent alerts)

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
3. **False Positive Suppression**: Trusted infrastructure modifier (CDN/cloud parents), query frequency threshold (popular domains)
4. **Threat Feeds**: URLhaus and CERT.PL integration
5. **OCSP Spike Detection**: Per-client hourly volume monitoring for OCSP domains
6. **Watched Domains**: Enhanced monitoring for potential C2 fronting / exfiltration vectors
7. **LLM Classification** (optional):
   - Fast triage model (phi3:3.8b) for initial classification
   - Escalation to thorough model (gpt-oss:20b) for suspicious domains
   - VirusTotal integration for additional context before escalation
   - Triage model auto-unloads after use (keep_alive + HTTP API) to free GPU/RAM
8. **Per-Domain Query Rate Spike**: Alerts when any client+domain pair exceeds hourly threshold (default: 100). Catches beaconing, DNS tunneling, forwarding loops.
9. **Message Lag Detection**: Compares syslog message timestamp to arrival time. Alerts when lag exceeds threshold (default: 5 minutes). Catches pipeline stalls and backlogs.

### OODA Watchdog

The watchdog is an optional **Observe-Orient-Decide-Act loop** that periodically sends traffic snapshots to Claude (via Anthropic API) for SOC-analyst-style evaluation. It sits above the rule-based analyzers as a holistic judgment layer.

**How it works:**
1. **Observe**: Queries DuckDB for a traffic snapshot (top domains, top clients, new domains, recent alerts) over a configurable window (default: 2x interval)
2. **Orient + Decide**: Sends the snapshot to Claude with a SOC analyst system prompt. Claude returns structured JSON with concerns, severity ratings, and recommended actions
3. **Act**: Creates alerts for concerns rated "alert" or "investigate". Can also suggest config tuning (e.g., adding false-positive domains to the allowlist via `tune_action: "add_allowlist"`)

**Key design decisions:**
- LLM call runs in a thread-pool executor so the event loop stays responsive
- Skips the LLM call entirely if no traffic in the observation window
- Tracks its own operational cost (tokens, latency, API spend) and includes this in the prompt — the LLM is self-aware of its resource usage
- Stores audit records of each cycle for observability

**Configuration**: `[watchdog]` section in config:
- `enabled`: Enable/disable (default: false)
- `interval_minutes`: Minutes between cycles (default: 15)
- `model`: Claude model to use (default: claude-sonnet-4-6)
- `max_tokens_per_cycle`: Max output tokens per LLM call (default: 4096)
- `window_minutes`: Traffic window to observe (default: 2x interval)

Requires `ANTHROPIC_API_KEY` env var or `[anthropic] api_key` in config.

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
- `[analyzer]`: Entropy thresholds, known-bad patterns, allowlists, trusted infrastructure, DGA suppression, OCSP spike detection, watched domains
- `[llm]`: Ollama models, escalation settings
- `[threat_feeds]`: URLhaus/CERT.PL integration
- `[virustotal]`: API key (prefer env var: `VIRUSTOTAL_API_KEY`)
- `[client_resolver]`: IP → hostname resolution
- `[device_activity]`: Activity anomaly detection
- `[retention]`: Data cleanup policies
- `[slack]`: Webhook notifications
- `[syslog]`: Receiver settings, message lag detection
- `[watchdog]`: OODA watchdog (periodic LLM-based traffic evaluation)

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
- Default: 1 hour deduplication window, 5000 alert cache size
- Prevents alert spam for repeated queries to same domain (e.g., `spclient.wg.spotify.com`)

### False Positive Reduction

- **Trusted infrastructure modifier**: High-entropy subdomains under known CDN/cloud parents (Akamai, Apple, CloudFront, AWS, etc.) are suppressed from DGA/entropy alerts. Configurable via `[analyzer] trusted_infrastructure`.
- **Query frequency threshold**: Domains queried >50 times from >5 unique clients are suppressed from DGA/entropy alerts. Genuine DGA rarely achieves consistent high-volume queries from many clients. Configurable via `dga_min_queries_suppress` and `dga_min_clients_suppress`.
- **LLM severity downgrade**: When enabled, LLM classification of benign/CDN/cloud domains downgrades alert severity.

### OCSP Spike Detection

- Monitors per-client query rates for OCSP domains (domains starting with `ocsp`)
- Fires once per client per domain when hourly count exceeds threshold (default: 100)
- Sudden OCSP spikes may indicate certificate pinning bypass attempts
- Configurable via `[analyzer] ocsp_spike_enabled`, `ocsp_spike_threshold`, `ocsp_spike_severity`

### Watched Domains

- Enhanced monitoring for domains that are legitimate but could be abused as C2 fronting or data-exfiltration vectors
- Supports exact match and wildcard suffix (`*.doubleclick.net`)
- Two detection types:
  - **First-query alert** (LOW): fires when a new client queries a watched domain for the first time
  - **Volume spike alert** (MEDIUM): fires when per-client hourly query count exceeds threshold (default: 50)
- Use cases: ad-tracking infrastructure (`*.doubleclick.net`), Google infrastructure used for domain fronting (`clients4.google.com`, `*.clients.l.google.com`)
- Configurable via `[analyzer] watched_domains`, `watched_domain_volume_threshold`

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
- VirusTotal API key should use env var (`VIRUSTOTAL_API_KEY`), not config file
- No sensitive data in logs (IP addresses logged at INFO level only in verbose mode)
- See `SECURITY.md` for full threat model and hardening recommendations
