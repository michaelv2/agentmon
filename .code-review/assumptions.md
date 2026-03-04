# Agentmon Assumption Template

> Review and update this file periodically. Each assumption should reflect
> what you *believe* the code does. The /review skill will verify these
> against the actual implementation.

---

## Syslog Collection

### Assumption: Messages are parsed with RFC 5424 first, falling back to RFC 3164
- **Expected behavior**: The receiver tries RFC 5424 structured format first, then falls back to BSD-style RFC 3164, then raw text
- **Edge cases I'm aware of**: Malformed UTF-8, oversized messages (>8KB dropped for ReDoS protection)
- **Open questions**: ~~What happens if a valid RFC 5424 message contains a hostname that doesn't match the source IP? Is this checked?~~ **Answered 2026-03-04**: Not checked. Parsed hostname and source_ip are stored independently with no validation. A spoofed hostname is accepted silently.

### Assumption: The IP allowlist blocks connections at the TCP level
- **Expected behavior**: If `allowed_ips` is configured, only those IPs can send syslog messages
- **Edge cases I'm aware of**: Empty allowlist should mean "allow all"
- **Open questions**: ~~Is the allowlist checked per-message or per-connection? Does it apply to both TCP and UDP?~~ **Answered 2026-03-04**: TCP: per-connection (checked in `connection_made()`, closed before data). UDP: per-datagram (checked in `datagram_received()`). Both protocols covered. No CIDR support — exact IP matching only.

---

## DNS Baseline Analyzer

### Assumption: Baselines are per-client, not global
- **Expected behavior**: Each client IP builds its own domain baseline. A domain seen by client A is still "new" for client B.
- **Edge cases I'm aware of**: None
- **Open questions**: ~~Is there a cap on baseline size per client? Could a scanner fill the baseline table?~~ **Answered 2026-03-04**: No cap. No retention cleanup on `domain_baseline` — kept forever. A scanner querying millions of unique domains would grow the table indefinitely.

### Assumption: Label-boundary matching prevents false positives on AWS EC2 reverse DNS
- **Expected behavior**: Pattern "c2-" matches "c2-server.net" but not "ec2-instance.amazonaws.com"
- **Edge cases I'm aware of**: None
- **Open questions**: ~~Does this apply to all known_bad_patterns or just specific ones?~~ **Answered 2026-03-04**: Applies to ALL patterns. `_matches_at_label_boundary()` is called for every pattern in `_check_known_bad()` at `dns_baseline.py:380`.

### Assumption: Alert deduplication prevents alert storms
- **Expected behavior**: TTL cache (10min default) prevents the same domain+client from generating multiple alerts
- **Edge cases I'm aware of**: Cache eviction under memory pressure
- **Open questions**: ~~Is dedup keyed on (domain, client) or just domain? What about different alert types for the same domain (e.g., entropy + threat feed)?~~ **Answered 2026-03-04**: Key is `(domain, client, alert_type)` — see `dns_baseline.py:208`. No cross-analyzer dedup: a single domain can generate up to 4 alerts simultaneously (threat_feed + known_bad + dga + new_domain). Cache is LRU at 5000 entries.

---

## LLM Classification

### Assumption: Two-tier classification runs triage first, escalates only when uncertain
- **Expected behavior**: phi3:3.8b does fast triage. If confidence < threshold or category is suspicious/unknown, escalates to gpt-oss:20b
- **Edge cases I'm aware of**: Ollama not running, model not loaded
- **Open questions**: ~~What happens if the triage model returns valid JSON but with an unexpected category value? Is the set of valid categories enforced?~~ **Answered 2026-03-04**: Invalid categories map to `UNKNOWN` via `DomainCategory` enum at `classifier.py:410-414`. Since `"unknown"` is in the default escalation list, unexpected categories always trigger escalation. Categories are enforced.

### Assumption: The triage model is unloaded after classification to free GPU
- **Expected behavior**: HTTP call with keep_alive=0 tells Ollama to unload the model
- **Edge cases I'm aware of**: Unload fails silently
- **Open questions**: ~~Is there a race condition if a new classification request arrives while unloading?~~ **Answered 2026-03-04**: Possible but non-fatal. Results are cached before unload (`classifier.py:312`), so same-domain requests hit cache. Different-domain requests may need to reload the model, adding latency. Unload failures are caught as debug.

### Assumption: VirusTotal is consulted via API if certain conditions are met
- **Edge cases I'm aware of**: VirusTotal may not return a response if it's being rate-limited
- **Open questions**: ~~Are these conditions unreachable?~~ **Answered 2026-03-04**: Conditions are reachable. VT is queried only during escalation (`classifier.py:317-322`) when `VIRUSTOTAL_API_KEY` is set and a domain triggers the escalation threshold.

---

## OODA Watchdog

### Assumption: The watchdog runs on a fixed interval and sends a traffic snapshot to Claude
- **Expected behavior**: Every N minutes, query DB for stats, format as JSON, send to Claude, parse response
- **Edge cases I'm aware of**: Claude API errors, rate limiting
- **Open questions**: ~~What happens if the watchdog cycle takes longer than the interval? Do cycles overlap or queue?~~ **Answered 2026-03-04**: No overlap. Loop is sequential at `ooda.py:534-568`: `run_cycle()` completes, then `asyncio.sleep(interval)`. Effective interval is `cycle_duration + sleep`. Long API calls cause drift, not overlap.

### Assumption: Watchdog tune actions (add_allowlist, add_known_bad) actually persist
- **Expected behavior**: When Claude suggests tuning, the config file is updated and the change takes effect
- **Edge cases I'm aware of**: File permission errors
- **Open questions**: ~~Does this trigger a SIGHUP reload? Or does it only affect the in-memory config? Will it survive a restart?~~ **Answered 2026-03-04**: Yes to all three. Writes to TOML atomically via `config.py:581-589`, then sends SIGHUP at `ooda.py:443`. Survives restart.

### Assumption: Watchdog alerts via Slack when necessary
- **Expected behavior**: If an action or observation meeting the config file threshold is satisfied, an alert will be pushed to the Slack webhook
- **Review finding 2026-03-04**: ⚠️ Watchdog does NOT send Slack alerts directly. It only creates Alert records in DuckDB via `store.insert_alert()` at `ooda.py:427`. Slack is handled inline in the `listen` event handler for DNS events only. Watchdog alerts appear in dashboard/CLI but do not trigger real-time Slack notifications.
- **Open questions**: ~~Will the Slack alert trigger if the watchdog LLM returns malformed JSON in its response?~~ **Answered 2026-03-04**: If JSON is malformed, `_parse_concerns()` catches the exception at `ooda.py:381`, logs a warning, returns empty list. Cycle continues with `action_taken="no_action"`.

---

## Parental Controls

### Assumption: Most-restrictive-wins when multiple policies apply to a device
- **Expected behavior**: If a device has two policies and one blocks "social" while the other allows it, "social" is blocked
- **Edge cases I'm aware of**: Overlapping time rules
- **Open questions**: ~~What happens when a device has a block-all rule during certain hours AND a category-specific rule during the same hours? Which takes precedence?~~ **Answered 2026-03-04**: Both are evaluated independently. `block_all` always fires during active time windows. Both alerts are collected and the highest severity wins. Consistent with most-restrictive-wins.

### Assumption: Time rules use the server's timezone
- **Expected behavior**: "15:00-17:00" means server local time
- **Edge cases I'm aware of**: DST transitions (is 2:30 AM during spring-forward in a blocked window?)
- **Open questions**: ~~Is timezone configurable per-device or per-policy?~~ **Answered 2026-03-04**: Not configurable. No timezone field in `TimeRule`, `ParentalPolicy`, or `Config`. Uses whatever timezone the event timestamp carries. RFC 3164 timestamps are naive (server local time). No DST handling — pure lexicographic comparison.

---

## Slack Notifications

### Assumption: Slack notifications are async and don't block the analysis pipeline
- **Expected behavior**: Alerts are sent via async HTTP POST, pipeline continues regardless of delivery
- **Edge cases I'm aware of**: Webhook URL invalid, Slack rate limiting, network partition
- **Open questions**: ~~Is there a retry mechanism? Or is it fire-and-forget? Are failed notifications logged?~~ **Answered 2026-03-04**: No retry. Fire-and-forget. Failed notifications logged at WARNING level (timeout, HTTP error, general exception) in `slack.py`.

---

## Configuration

### Assumption: Hot-reload via SIGHUP only applies to tunable fields
- **Expected behavior**: Structural fields (port, db path, etc.) require restart. Tunable fields (allowlist, thresholds, etc.) can be reloaded.
- **Edge cases I'm aware of**: TOML parse error during reload
- **Review finding 2026-03-04**: ⚠️ `cli.py:877` replaces the entire `cfg` object on SIGHUP, not just tunable fields. Structural fields like `retention_dns_events_days` silently change in memory. The periodic cleanup task reads `cfg` by reference and will use new values.
- **Open questions**: ~~What happens if a hot-reload changes the allowlist while an analysis batch is in progress? Is there a consistency boundary?~~ **Answered 2026-03-04**: No consistency boundary. SIGHUP handler mutates analyzer fields one-at-a-time on the event loop between iterations. A batch in progress could see partial updates. TOML parse errors return current config unchanged.

### Assumption: Environment variables override config file values for secrets
- **Expected behavior**: AGENTMON_SLACK_WEBHOOK, VIRUSTOTAL_API_KEY, ANTHROPIC_API_KEY, OLLAMA_HOST from env override TOML
- **Edge cases I'm aware of**: None
- **Open questions**: ~~If the env var is set to empty string, does it override with empty or fall back to TOML?~~ **Answered 2026-03-04**: Empty string does NOT override — falsy check `if env_slack_webhook:` at `config.py:251`. Falls back to TOML. Correct behavior.

---

## Storage

### Assumption: DuckDB handles concurrent read/write safely
- **Expected behavior**: Read-only connections copy DB to temp file to avoid writer locks
- **Edge cases I'm aware of**: Temp file cleanup, disk space
- **Open questions**: ~~Is the temp copy atomic? What happens if the writer is mid-transaction when the reader copies?~~ **Answered 2026-03-04**: NOT atomic. `.db` and `.wal` are copied sequentially via `shutil.copy2()` at `db.py:55-59`. A write between the two copies could produce an inconsistent snapshot. DuckDB checksumming may catch this, but not guaranteed.

### Assumption: Schema versioning handles upgrades gracefully
- **Expected behavior**: SCHEMA_VERSION is checked and migrations run if needed
- **Edge cases I'm aware of**: Downgrade (newer schema, older code)
- **Open questions**: ~~What happens if migration fails partway through? Is it transactional?~~ **Answered 2026-03-04**: NOT transactional. Uses `CREATE TABLE IF NOT EXISTS` so partial failure retries on next startup. Downgrade: version check is false, code runs silently with newer schema — could cause runtime errors. No rollback mechanism. Current migrations are idempotent, but future ALTER TABLE changes would not be.

---

## Threat Feeds

### Assumption: Threat feeds are downloaded atomically (temp file + rename)
- **Expected behavior**: Partial downloads don't corrupt the active feed file
- **Edge cases I'm aware of**: Disk full during download
- **Open questions**: ~~What happens if the feed URL returns 200 but with empty/invalid content? Is the existing feed preserved?~~ **Answered 2026-03-04**: Existing feed is NOT preserved. A 200 with empty/garbage body overwrites the cache file. `_load_cache()` filters lines, so garbage produces an empty domain set. A single bad response wipes the feed until the next successful update.

---

## Assumptions added from 2026-03-04 review

> These were discovered during the review and were not previously tracked.

### Assumption: The TCP syslog receiver is resistant to memory exhaustion
- **Expected behavior**: Malicious or misbehaving clients can't OOM the process
- **Review finding 2026-03-04**: ❌ **Incorrect.** `TCPSyslogProtocol.data_received` at `syslog_receiver.py:262-275` appends to `self.buffer` with no size limit. A sender that never sends `\n` grows the buffer until OOM. `MAX_SYSLOG_MESSAGE_LENGTH` only applies after line extraction.

### Assumption: The watchdog's Anthropic API call is non-blocking
- **Expected behavior**: The event loop continues processing syslog while waiting for Claude
- **Review finding 2026-03-04**: ❌ **Incorrect.** `self.llm.complete_with_usage()` at `ooda.py:196` is a synchronous HTTP call that blocks the entire asyncio event loop for 2-10 seconds per cycle.

### Assumption: Dashboard endpoints require authentication
- **Expected behavior**: State-mutating endpoints (acknowledge, false-positive, allowlist, llm-review) are protected
- **Review finding 2026-03-04**: ❌ **Incorrect.** Dashboard has zero authentication. All endpoints are publicly accessible. The `/api/domain/{domain}/allowlist` endpoint writes directly to TOML and reloads config.

### Assumption: Overnight parental control rules span midnight correctly
- **Expected behavior**: `days=["fri"], start=22:00, end=07:00` blocks Friday night through Saturday morning
- **Review finding 2026-03-04**: ❌ **Incorrect.** At Saturday 3am, `weekday=5` (Saturday) is not in `[4]` (Friday), so the rule doesn't match. The day-of-week check at `parental_analyzer.py:221` doesn't account for the day boundary on overnight rules.

### Assumption: The watchdog sends Slack alerts for its findings
- **Expected behavior**: Watchdog concerns that generate alerts also trigger Slack notifications
- **Review finding 2026-03-04**: ❌ **Incorrect.** Watchdog only writes Alert records to DuckDB. There is no Slack notification path for watchdog-generated alerts.

### Assumption: LLM confidence values are validated to [0.0, 1.0]
- **Expected behavior**: Ollama-returned confidence is clamped before use
- **Review finding 2026-03-04**: ❌ **Incorrect.** `classifier.py:419` parses confidence as `float()` with no range check. A value of `99.0` suppresses escalation; `-5.0` always escalates. A compromised Ollama instance can control classification flow.
