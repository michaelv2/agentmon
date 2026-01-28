# Smart Analysis Improvements

This document covers improvements to agentmon's learning and analysis capabilities:

1. **Client Identity Resolution** - Use hostnames instead of IPs to survive DHCP changes *(implemented)*
2. **Device Activity Anomaly Detection** - Learn normal activity patterns and alert on deviations *(implemented)*
3. **Data Retention Policy** - Tiered storage to balance learning needs with disk usage *(planned)*

---

## Problem: DHCP Breaks Per-Client Learning

The existing `domain_baseline` table uses client IP as a key:

```sql
PRIMARY KEY (client, domain)  -- client is IP address
```

When DHCP reassigns IPs, learned patterns become meaningless:
- alice-laptop's known domains are now attributed to bob-phone
- bob-phone triggers false "new domain" alerts
- Detection quality degrades over time

**This affects both existing baseline learning AND the proposed device activity detection.**

---

## Part 1: Client Identity Resolution (IMPLEMENTED)

> **Status:** Implemented. See `agentmon/resolver.py` for the full implementation.

### Overview

Resolves client IPs to stable hostnames so baselines survive DHCP changes.

```
DNS Event (client_ip: 192.168.1.50)
    → ClientResolver.resolve("192.168.1.50")
    → PTR lookup: "alice-laptop.lan"
    → Return "alice-laptop" as stable identifier
    → Use for all baseline lookups
```

**Fallback chain:**
1. Explicit config mapping (highest priority)
2. Reverse DNS (PTR) lookup against local DNS
3. Raw IP address (fallback for devices without PTR records)

### Configuration

```toml
[client_resolver]
enabled = true

# DNS server for reverse lookups (usually Pi-hole)
# Leave unset to use system default resolver
# dns_server = "192.168.1.1"

# Cache TTL for resolved hostnames (seconds)
cache_ttl = 3600  # 1 hour

# Strip domain suffix from hostnames
# "alice-laptop.lan" → "alice-laptop"
strip_suffix = true

# Explicit overrides (highest priority)
# Use for devices that don't register hostnames via DHCP
[[client_resolver.mappings]]
ip = "192.168.1.100"
name = "media-server"

[[client_resolver.mappings]]
ip = "192.168.1.101"
name = "iot-hub"
```

### Key Implementation Files

| File | Purpose |
|------|---------|
| `agentmon/resolver.py` | ClientResolver class with caching |
| `agentmon/config.py` | Configuration parsing |
| `agentmon/cli.py` | CLI integration |
| `config/agentmon.example.toml` | Configuration documentation |

### How It Works

1. **Initialization:** ClientResolver is initialized in `cli.py` when `[client_resolver] enabled = true`
2. **Resolution:** For each DNS event, the client IP is resolved before analysis
3. **Caching:** Positive lookups are cached (default 1 hour), failed lookups have a 5-minute negative cache
4. **Fallback:** If resolution fails, the original IP is used

### Database Migration

Existing `domain_baseline` data keyed by IP becomes stale after enabling hostname resolution. Options:

1. **Clear and re-learn** (simplest):
   ```bash
   duckdb ~/.local/share/agentmon/events.db "DELETE FROM domain_baseline"
   ```
2. **Migrate in-place** (complex): Update client column with resolved hostnames

Recommend option 1 - baseline rebuilds quickly (days, not weeks).

---

## Part 2: Device Activity Anomaly Detection (IMPLEMENTED)

> **Status:** Implemented in commit `c34944c`. See `agentmon/analyzers/device_activity.py` for the full implementation.

### Overview

Learns each device's "normal" activity hours and alerts when activity occurs outside those patterns - without requiring hard-coded time rules.

**Example:**
- alice-laptop normally active 7am-10pm on weekdays
- At 3:15 AM Tuesday, suddenly starts querying domains
- Alert: "Unusual activity: alice-laptop active at 03:00 (normally inactive)"

### Relationship to Parental Controls

| Feature | Parental Controls | Device Activity Anomaly |
|---------|-------------------|------------------------|
| Approach | Hard-coded rules | Learned baseline |
| Config | Manual time windows | Auto-learned from data |
| Use case | "Block games 3-5pm" | "Alert if active at 3am" |
| Setup | Requires policy config | Just enable and wait |

Both can run simultaneously.

### Configuration

```toml
[device_activity]
enabled = true

# Learning period before generating alerts (days)
learning_days = 14

# Minimum queries in an hour to consider device "active"
activity_threshold = 5

# Minimum samples per time slot before detecting anomalies
min_samples = 7

# Alert severity for activity anomalies
alert_severity = "medium"

# Named devices for better alert messages
[[device_activity.devices]]
name = "alice-laptop"
client_ips = ["192.168.1.50"]

[[device_activity.devices]]
name = "bob-phone"
client_ips = ["192.168.1.51", "192.168.1.52"]  # Multiple IPs (DHCP)

[[device_activity.devices]]
name = "media-server"
client_ips = ["192.168.1.100"]
always_active = true  # Servers expected to be active 24/7
```

### Database Schema

**Table: `device_activity_baseline`**

```sql
CREATE TABLE IF NOT EXISTS device_activity_baseline (
    client VARCHAR NOT NULL,
    day_of_week INTEGER NOT NULL,   -- 0=Monday through 6=Sunday
    hour_of_day INTEGER NOT NULL,   -- 0-23
    query_count INTEGER DEFAULT 0,  -- Total queries observed in this slot
    active_count INTEGER DEFAULT 0, -- Times this slot was "active"
    sample_count INTEGER DEFAULT 0, -- Times this slot was observed
    first_seen TIMESTAMP,
    last_updated TIMESTAMP,
    PRIMARY KEY (client, day_of_week, hour_of_day)
)
```

**Size:** Maximum 168 rows per device (7 days × 24 hours). For 100 devices = 16,800 rows. Negligible.

### How It Works

1. **Learning Phase** (first 14 days by default):
   - Each hour, count DNS queries per device
   - At hour boundary, mark time slot as "active" if queries >= threshold
   - Record observations without generating alerts

2. **Detection Phase** (after learning period):
   - Calculate `active_ratio = active_count / sample_count` for each time slot
   - If device is active in a slot where `active_ratio < 10%`, generate anomaly alert
   - Continue updating baseline with new observations

3. **Alert Generation:**
   - Title: "Unusual activity: alice-laptop active at 03:00"
   - Description includes query count and historical activity ratio
   - Confidence based on how rarely the slot is normally active

### Key Implementation Files

| File | Purpose |
|------|---------|
| `agentmon/analyzers/device_activity.py` | DeviceActivityAnalyzer class |
| `agentmon/storage/db.py` | Database methods for baseline storage |
| `agentmon/config.py` | Configuration parsing |
| `agentmon/cli.py` | CLI integration |
| `config/agentmon.example.toml` | Configuration documentation |

---

## Part 3: Data Retention Policy (IMPLEMENTED)

> **Status:** Implemented. See `agentmon/storage/db.py` and `agentmon/cli.py` for the full implementation.

### Overview

Tiered storage model that balances learning needs with disk usage. Raw events are cleaned up automatically while baselines are preserved indefinitely (they're bounded by design).

### Tiered Storage Model

| Tier | Data | Retention | Purpose |
|------|------|-----------|---------|
| Raw events | `dns_events` | 7-30 days | Investigation, debugging |
| Alerts | `alerts` | 90 days | Incident history |
| Domain baseline | `domain_baseline` | Indefinite | First-seen detection (bounded) |
| Activity baseline | `device_activity_baseline` | Indefinite | Pattern learning (bounded) |

### Configuration

```toml
[retention]
# Raw DNS events - keep for investigation/debugging
dns_events_days = 30

# Alerts - keep for incident history
alerts_days = 90

# Run cleanup at startup and then every N hours
cleanup_interval_hours = 24
```

### Key Implementation Files

| File | Purpose |
|------|---------|
| `agentmon/storage/db.py` | `cleanup_old_data()` and `vacuum()` methods |
| `agentmon/config.py` | Configuration parsing for `[retention]` section |
| `agentmon/cli.py` | `cleanup` command + periodic cleanup in `listen` |
| `config/agentmon.example.toml` | Configuration documentation |

### How It Works

1. **Manual Cleanup:** Run `agentmon cleanup` to delete old data on demand
2. **Startup Cleanup:** When `listen` starts with retention enabled, old data is cleaned
3. **Periodic Cleanup:** Background task runs every `cleanup_interval_hours`
4. **VACUUM:** Optional `--vacuum` flag reclaims disk space after deletion

---

## Files to Create/Modify

| File | Action | Status | Purpose |
|------|--------|--------|---------|
| `agentmon/resolver.py` | Create | **Done** | ClientResolver class for IP→hostname |
| `agentmon/analyzers/device_activity.py` | Create | **Done** | DeviceActivityAnalyzer class |
| `agentmon/storage/db.py` | Modify | **Done** | Add activity table + cleanup methods |
| `agentmon/config.py` | Modify | **Done** | Add resolver, activity, retention config |
| `agentmon/cli.py` | Modify | **Done** | Wire up resolver, analyzer, cleanup |
| `config/agentmon.example.toml` | Modify | **Done** | Document new config sections |

---

## Verification

### 1. Client Resolution Test (IMPLEMENTED)

```bash
# 1. Enable client resolver in config
cat >> ~/.config/agentmon/agentmon.toml << 'EOF'
[client_resolver]
enabled = true
cache_ttl = 3600
strip_suffix = true
EOF

# 2. Verify reverse DNS works for your devices
nslookup 192.168.1.50 192.168.1.1
# Should return: alice-laptop.lan (or similar)

# 3. Start agentmon with verbose output
agentmon listen --port 1514 --verbose
# Logs should show: "Resolved: 192.168.1.50 → alice-laptop"
```

### 2. Baseline Migration Test (IMPLEMENTED)

```bash
# Before enabling hostname resolution - check current baselines
duckdb ~/.local/share/agentmon/events.db \
  "SELECT DISTINCT client FROM domain_baseline LIMIT 10"
# Shows: 192.168.1.50, 192.168.1.51, ...

# Enable hostname resolution, clear old baseline
duckdb ~/.local/share/agentmon/events.db \
  "DELETE FROM domain_baseline"

# Start agentmon with resolver enabled
agentmon listen --port 1514

# After running for a day, check baselines
duckdb ~/.local/share/agentmon/events.db \
  "SELECT DISTINCT client FROM domain_baseline LIMIT 10"
# Shows: alice-laptop, bob-phone, ... (hostnames instead of IPs)
```

### 3. Activity Anomaly Test (IMPLEMENTED)

```bash
# 1. Enable device activity in config
cat >> ~/.config/agentmon/agentmon.toml << 'EOF'
[device_activity]
enabled = true
learning_days = 14
activity_threshold = 5
min_samples = 7
alert_severity = "medium"

[[device_activity.devices]]
name = "test-device"
client_ips = ["192.168.1.50"]
EOF

# 2. Start agentmon with device activity enabled
agentmon listen --port 1514

# 3. Wait for learning period (14 days of normal activity)

# 4. After learning period, simulate off-hours activity
# (send DNS queries at 3am from a normally-sleeping device)
# Should generate: "Unusual activity: test-device active at 03:00"

# 5. Check database for learned baselines
duckdb ~/.local/share/agentmon/events.db \
  "SELECT client, day_of_week, hour_of_day, active_count, sample_count
   FROM device_activity_baseline
   WHERE client = '192.168.1.50'"
```

### 4. Retention Test (IMPLEMENTED)

```bash
# 1. Check current data stats
agentmon cleanup --dry-run

# 2. Run cleanup with custom retention periods
agentmon cleanup --dns-days 7 --alerts-days 30

# 3. Reclaim disk space
agentmon cleanup --dns-days 7 --alerts-days 30 --vacuum

# 4. Enable automatic cleanup in config
cat >> ~/.config/agentmon/agentmon.toml << 'EOF'
[retention]
enabled = true
dns_events_days = 30
alerts_days = 90
cleanup_interval_hours = 24
EOF

# 5. Start agentmon - cleanup runs at startup and every 24 hours
agentmon listen --port 1514
```

---

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Client Identity Resolution | **Implemented** | See `agentmon/resolver.py` |
| Device Activity Anomaly | **Implemented** | See `agentmon/analyzers/device_activity.py` |
| Data Retention Policy | **Implemented** | See `agentmon/storage/db.py` |

## Rollout Plan

1. ~~**Phase 1: Client Resolution**~~ **COMPLETE**
   - Implemented in `agentmon/resolver.py`
   - Enable with `[client_resolver] enabled = true` in config
   - Clear old baseline: `DELETE FROM domain_baseline`

2. ~~**Phase 2: Device Activity Anomaly**~~ **COMPLETE**
   - Implemented in `agentmon/analyzers/device_activity.py`
   - Enable with `[device_activity] enabled = true` in config
   - See `config/agentmon.example.toml` for full configuration options

3. ~~**Phase 3: Data Retention**~~ **COMPLETE**
   - Implemented in `agentmon/storage/db.py` and `agentmon/cli.py`
   - Enable with `[retention] enabled = true` in config
   - Manual cleanup: `agentmon cleanup --dns-days 7 --vacuum`
