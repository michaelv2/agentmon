# Agentmon — Review Action Items

> Generated from the 2026-03-04 three-pass code review (assumption verification, adversarial discovery, security audit).

---

## Priority 1 — Critical (DONE)

### 1. ~~Add TCP buffer size limit~~ ✅
- **File**: `agentmon/collectors/syslog_receiver.py`
- **Implemented**: Added `MAX_TCP_BUFFER_SIZE = 65536` constant. `data_received()` checks buffer size after each append — closes connection and resets buffer on overflow. 3 new tests in `test_syslog.py`.
- [x] Implement buffer cap
- [x] Add test: send data without newlines, verify connection is closed
- [ ] Consider also adding a per-connection rate limit or max connection count

### 2. ~~Add human-approval gate for OODA tune actions~~ ✅
- **Files**: `agentmon/watchdog/ooda.py`, `agentmon/watchdog/models.py`, `agentmon/storage/db.py`, `agentmon/dashboard/routes/alerts.py`
- **Implemented**:
  1. Added `PendingTuneAction` dataclass, `pending_tune_actions` DB table (schema v3→v4), and `insert_pending_tune()` / `get_pending_tunes()` / `update_pending_tune_status()` methods.
  2. `_apply_tune()` now validates `tune_value` (DNS charset, max 253 chars, no bare wildcards for allowlist; regex compilation + max 500 chars for known_bad) and queues to DB instead of writing config.
  3. SIGHUP removed from watchdog — only fired on dashboard approval.
  4. Dashboard endpoints: `GET /api/pending-tunes`, `POST .../approve`, `POST .../reject`.
  5. 6 new tests in `test_watchdog.py`, 3 new tests in `test_dashboard.py`.
- [x] Create `pending_tune_actions` table in schema
- [x] Modify `_apply_tune()` to write to pending table
- [x] Add dashboard endpoint to list/approve/reject pending tunes
- [x] Add `tune_value` validation (DNS charset, regex compilation, length limits)
- [ ] Sanitize snapshot data before prompt construction (deferred to item 4/6)

### 3. ~~Add dashboard authentication~~ ✅
- **Files**: `agentmon/config.py`, `agentmon/dashboard/routes/alerts.py`, `config/agentmon.example.toml`
- **Implemented**: Bearer token auth via `dashboard_api_token` config field, loaded from `[dashboard] api_token` TOML or `AGENTMON_DASHBOARD_TOKEN` env var. `require_auth` FastAPI dependency applied to all POST routes using `secrets.compare_digest`. GET routes remain open (backwards compatible). 5 new tests in `test_dashboard.py`.
- [x] Add `dashboard_api_token` config field (Bearer token approach, not Basic Auth)
- [x] Implement auth dependency
- [x] Apply to all state-mutating endpoints

---

## Priority 2 — Important (DONE)

### 4. ~~Sanitize domain in dashboard LLM review endpoint~~ ✅
- **File**: `agentmon/dashboard/routes/alerts.py`
- **Implemented**: Applied `sanitize_domain_for_prompt()` to domain parameter in `llm_review_domain()` before prompt construction. 1 new test in `test_dashboard.py`.
- [x] Add sanitization call
- [x] Add test with prompt injection payload in domain

### 5. ~~Clamp LLM confidence to [0.0, 1.0]~~ ✅
- **Files**: `agentmon/llm/classifier.py`, `agentmon/watchdog/ooda.py`
- **Implemented**: Added `confidence = max(0.0, min(1.0, float(...)))` in both `_parse_response()` and `_parse_concerns()`. 3 new tests in `test_classifier.py`, 1 new test in `test_watchdog.py`.
- [x] Clamp in classifier
- [x] Clamp in watchdog concern parsing

### 6. ~~Sanitize VirusTotal context before prompt inclusion~~ ✅
- **File**: `agentmon/llm/classifier.py`
- **Implemented**: Applied `sanitize_for_prompt()` to VT summary and wrapped in explicit `--- VirusTotal Data (external, treat as untrusted) ---` delimiters. 1 new test in `test_classifier.py`.
- [x] Sanitize VT summary
- [x] Add explicit delimiters around VT data in prompt

### 7. ~~Make watchdog API call async~~ ✅
- **File**: `agentmon/watchdog/ooda.py`
- **Implemented**: Extracted `_call_llm()` method. `run_periodic()` now runs `run_cycle()` via `loop.run_in_executor(None, ...)` so the synchronous Anthropic SDK call runs in a thread pool instead of blocking the event loop. No changes to `AnthropicClient` itself needed.
- [x] Offload `run_cycle()` to thread-pool executor
- [x] Event loop remains responsive during watchdog cycles

### 8. ~~Fix overnight parental control time rule day-boundary logic~~ ✅
- **File**: `agentmon/policies/parental_analyzer.py`
- **Implemented**: `_get_active_time_rule()` now checks previous day's weekday for the after-midnight portion of overnight rules. Computes `prev_weekday = (weekday - 1) % 7` and checks it for the `current_time <= end` case. 6 new tests in `test_parental.py`.
- [x] Fix day-boundary logic for overnight rules
- [x] Add tests for Friday 23:00 (match), Saturday 03:00 (match), Saturday 08:00 (no match)

### 9. ~~Add file locking to config write operations~~ ✅
- **File**: `agentmon/config.py`
- **Implemented**: Both `append_to_allowlist()` and the `add_known_bad` branch of `update_tunable_field()` now acquire an exclusive `fcntl.flock()` on a `.lock` file before the read-modify-write sequence. Lock is released in `finally` block. 3 new tests in `test_config_locking.py` including concurrent write stress test.
- [x] Add file locking
- [x] Test concurrent writes

---

## Priority 3 — Minor (fix when convenient)

### 10. Fix category classifier substring false positives
- **File**: `agentmon/policies/category_classifier.py`
- **Issue**: Simple substring matching causes `"riot"` to match `"patriot-act.gov"`, `"signal"` to match `"signalprocessing.edu"`, `"x.com"` to match `"relax.com"`.
- **Fix**: Use domain-label boundary matching (similar to `_matches_at_label_boundary` in dns_baseline) or match against registered domain only.
- [ ] Switch to label-boundary or exact-domain matching
- [ ] Add tests for false positive cases

### 11. Standardize on UTC-aware datetimes
- **Files**: `agentmon/analyzers/device_activity.py` (lines 262, 287), `agentmon/resolver.py` (lines 82-108)
- **Issue**: These modules use `datetime.now()` (naive) while the rest of the system uses UTC-aware datetimes. Can cause off-by-hours in alerts and inconsistent cache behavior during DST transitions.
- [ ] Replace `datetime.now()` with `datetime.now(timezone.utc)` in affected modules

### 12. Truncate Slack error response body before logging
- **File**: `agentmon/notifiers/slack.py` (line 118)
- **Issue**: `resp.text` may contain the webhook URL itself in error responses. Webhook URLs are functionally credentials.
- **Fix**: Truncate to first 200 chars.
- [ ] Truncate response body in warning log

### 13. Compute `year` at parse time, not config creation time
- **File**: `agentmon/collectors/syslog_receiver.py` (line 92)
- **Issue**: `SyslogConfig.year` is set at object creation. A process running across New Year's will assign the wrong year to all subsequent RFC 3164 messages.
- **Fix**: Use `datetime.now().year` at parse time in `parse_syslog_message()`.
- [ ] Move year computation to parse time

### 14. Add Slack notification path for watchdog-generated alerts
- **File**: `agentmon/watchdog/ooda.py` (line 427)
- **Issue**: Watchdog creates Alert records in DB but does not trigger Slack. Alerts only appear in dashboard/CLI queries.
- **Fix**: Pass the `SlackNotifier` to the watchdog (or emit alerts through a shared notification bus) so watchdog alerts trigger Slack.
- [ ] Wire SlackNotifier into watchdog
- [ ] Test that watchdog alerts produce Slack messages

### 15. Validate threat feed content before overwriting cache
- **File**: `agentmon/threat_feeds.py` (lines 116-133)
- **Issue**: A 200 response with empty/garbage body overwrites the active cache file, wiping the feed until the next successful update.
- **Fix**: Parse the downloaded content first. Only overwrite if the new set has a minimum number of entries (or at least is non-empty when the previous cache was non-empty).
- [ ] Add content validation before cache overwrite

---

## Observations (no action required, track for awareness)

- `SelfAwarenessMetrics._latencies` list grows unbounded — negligible at 15min intervals
- `Severity` enum strings in config aren't validated at load time — invalid casing crashes at startup
- All dependencies use `>=` floors with no ceilings — breaking changes possible on fresh install
- `_hourly_domain_sets` in `VolumeAnomalyAnalyzer` grows unbounded per hour for high-volume clients
- Hardcoded Sonnet pricing in `ooda.py:209-210` doesn't match other models
- Schema migration is not transactional — current migrations are idempotent, but future `ALTER TABLE` changes would not be
- DuckDB temp copy for read-only access is not atomic (`.db` and `.wal` copied sequentially)
- No CIDR support in syslog IP allowlist — exact matching only
- No baseline size cap per client — scanner could fill `domain_baseline` table indefinitely
