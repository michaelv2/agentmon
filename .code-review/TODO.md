# Agentmon — Review Action Items

> Generated from the 2026-03-04 three-pass code review (assumption verification, adversarial discovery, security audit).

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
