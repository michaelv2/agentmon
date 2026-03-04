# Agentmon Assumption Template

> Review and update this file periodically. Each assumption should reflect
> what you *believe* the code does. The /review skill will verify these
> against the actual implementation.

---

## Syslog Collection

### Assumption: Messages are parsed with RFC 5424 first, falling back to RFC 3164
- **Expected behavior**: The receiver tries RFC 5424 structured format first, then falls back to BSD-style RFC 3164, then raw text
- **Edge cases I'm aware of**: Malformed UTF-8, oversized messages (>8KB dropped for ReDoS protection)
- **Open questions**: What happens if a valid RFC 5424 message contains a hostname that doesn't match the source IP? Is this checked?

### Assumption: The IP allowlist blocks connections at the TCP level
- **Expected behavior**: If `allowed_ips` is configured, only those IPs can send syslog messages
- **Edge cases I'm aware of**: Empty allowlist should mean "allow all"
- **Open questions**: Is the allowlist checked per-message or per-connection? Does it apply to both TCP and UDP?

---

## DNS Baseline Analyzer

### Assumption: Baselines are per-client, not global
- **Expected behavior**: Each client IP builds its own domain baseline. A domain seen by client A is still "new" for client B.
- **Edge cases I'm aware of**: None
- **Open questions**: Is there a cap on baseline size per client? Could a scanner fill the baseline table?

### Assumption: Label-boundary matching prevents false positives on AWS EC2 reverse DNS
- **Expected behavior**: Pattern "c2-" matches "c2-server.net" but not "ec2-instance.amazonaws.com"
- **Edge cases I'm aware of**: None
- **Open questions**: Does this apply to all known_bad_patterns or just specific ones?

### Assumption: Alert deduplication prevents alert storms
- **Expected behavior**: TTL cache (10min default) prevents the same domain+client from generating multiple alerts
- **Edge cases I'm aware of**: Cache eviction under memory pressure
- **Open questions**: Is dedup keyed on (domain, client) or just domain? What about different alert types for the same domain (e.g., entropy + threat feed)?

---

## LLM Classification

### Assumption: Two-tier classification runs triage first, escalates only when uncertain
- **Expected behavior**: phi3:3.8b does fast triage. If confidence < threshold or category is suspicious/unknown, escalates to gpt-oss:20b
- **Edge cases I'm aware of**: Ollama not running, model not loaded
- **Open questions**: What happens if the triage model returns valid JSON but with an unexpected category value? Is the set of valid categories enforced?

### Assumption: The triage model is unloaded after classification to free GPU
- **Expected behavior**: HTTP call with keep_alive=0 tells Ollama to unload the model
- **Edge cases I'm aware of**: Unload fails silently
- **Open questions**: Is there a race condition if a new classification request arrives while unloading?

---

## OODA Watchdog

### Assumption: The watchdog runs on a fixed interval and sends a traffic snapshot to Claude
- **Expected behavior**: Every N minutes, query DB for stats, format as JSON, send to Claude, parse response
- **Edge cases I'm aware of**: Claude API errors, rate limiting
- **Open questions**: What happens if the watchdog cycle takes longer than the interval? Do cycles overlap or queue?

### Assumption: Watchdog tune actions (add_allowlist, add_known_bad) actually persist
- **Expected behavior**: When Claude suggests tuning, the config file is updated and the change takes effect
- **Edge cases I'm aware of**: File permission errors
- **Open questions**: Does this trigger a SIGHUP reload? Or does it only affect the in-memory config? Will it survive a restart?

---

## Parental Controls

### Assumption: Most-restrictive-wins when multiple policies apply to a device
- **Expected behavior**: If a device has two policies and one blocks "social" while the other allows it, "social" is blocked
- **Edge cases I'm aware of**: Overlapping time rules
- **Open questions**: What happens when a device has a block-all rule during certain hours AND a category-specific rule during the same hours? Which takes precedence?

### Assumption: Time rules use the server's timezone
- **Expected behavior**: "15:00-17:00" means server local time
- **Edge cases I'm aware of**: DST transitions (is 2:30 AM during spring-forward in a blocked window?)
- **Open questions**: Is timezone configurable per-device or per-policy?

---

## Slack Notifications

### Assumption: Slack notifications are async and don't block the analysis pipeline
- **Expected behavior**: Alerts are sent via async HTTP POST, pipeline continues regardless of delivery
- **Edge cases I'm aware of**: Webhook URL invalid, Slack rate limiting, network partition
- **Open questions**: Is there a retry mechanism? Or is it fire-and-forget? Are failed notifications logged?

---

## Configuration

### Assumption: Hot-reload via SIGHUP only applies to tunable fields
- **Expected behavior**: Structural fields (port, db path, etc.) require restart. Tunable fields (allowlist, thresholds, etc.) can be reloaded.
- **Edge cases I'm aware of**: TOML parse error during reload
- **Open questions**: What happens if a hot-reload changes the allowlist while an analysis batch is in progress? Is there a consistency boundary?

### Assumption: Environment variables override config file values for secrets
- **Expected behavior**: AGENTMON_SLACK_WEBHOOK, VIRUSTOTAL_API_KEY, ANTHROPIC_API_KEY, OLLAMA_HOST from env override TOML
- **Edge cases I'm aware of**: None
- **Open questions**: If the env var is set to empty string, does it override with empty or fall back to TOML?

---

## Storage

### Assumption: DuckDB handles concurrent read/write safely
- **Expected behavior**: Read-only connections copy DB to temp file to avoid writer locks
- **Edge cases I'm aware of**: Temp file cleanup, disk space
- **Open questions**: Is the temp copy atomic? What happens if the writer is mid-transaction when the reader copies?

### Assumption: Schema versioning handles upgrades gracefully
- **Expected behavior**: SCHEMA_VERSION is checked and migrations run if needed
- **Edge cases I'm aware of**: Downgrade (newer schema, older code)
- **Open questions**: What happens if migration fails partway through? Is it transactional?

---

## Threat Feeds

### Assumption: Threat feeds are downloaded atomically (temp file + rename)
- **Expected behavior**: Partial downloads don't corrupt the active feed file
- **Edge cases I'm aware of**: Disk full during download
- **Open questions**: What happens if the feed URL returns 200 but with empty/invalid content? Is the existing feed preserved?
