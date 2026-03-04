#!/usr/bin/env bash
# watchdog-snapshot.sh — Gather a full agentmon traffic snapshot for OODA cycles.
# Usage: ./scripts/watchdog-snapshot.sh [WINDOW_MINUTES] [DB_PATH]
set -euo pipefail

WINDOW="${1:-30}"
DB_PATH="${2:-$HOME/.local/share/agentmon/events.db}"

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: Database not found at $DB_PATH"
    exit 1
fi

# Copy DB to temp file to avoid lock conflicts with running agentmon listen.
# DuckDB doesn't support concurrent read + write on the same file;
# this mirrors the EventStore.connect(read_only=True) strategy in Python.
# Use ~/.cache so snap-confined duckdb can access the path.
SNAP_DIR="${HOME}/.cache/agentmon-snapshot.$$"
mkdir -p "$SNAP_DIR"
trap 'rm -rf "$SNAP_DIR"' EXIT
cp "$DB_PATH" "$SNAP_DIR/events.db"
# Also copy WAL if present (contains uncommitted writes)
[[ -f "${DB_PATH}.wal" ]] && cp "${DB_PATH}.wal" "$SNAP_DIR/events.db.wal"

DDB="duckdb $SNAP_DIR/events.db"

echo "=== ACTIVITY SUMMARY (last ${WINDOW} min) ==="
$DDB <<SQL
SELECT
    COUNT(*)                                      AS total_queries,
    COUNT(DISTINCT domain)                        AS unique_domains,
    SUM(CASE WHEN blocked THEN 1 ELSE 0 END)     AS blocked,
    COUNT(DISTINCT client)                        AS active_clients
FROM dns_events
WHERE timestamp > NOW() - INTERVAL '${WINDOW} minutes';
SQL

echo ""
echo "=== TOP CLIENTS ==="
$DDB <<SQL
SELECT
    client,
    COUNT(*)                AS queries,
    COUNT(DISTINCT domain)  AS domains,
    SUM(CASE WHEN blocked THEN 1 ELSE 0 END) AS blocked
FROM dns_events
WHERE timestamp > NOW() - INTERVAL '${WINDOW} minutes'
GROUP BY client
ORDER BY queries DESC
LIMIT 10;
SQL

echo ""
echo "=== TOP DOMAINS ==="
$DDB <<SQL
SELECT
    domain,
    COUNT(*)                AS queries,
    COUNT(DISTINCT client)  AS clients,
    BOOL_OR(blocked)        AS blocked
FROM dns_events
WHERE timestamp > NOW() - INTERVAL '${WINDOW} minutes'
GROUP BY domain
ORDER BY queries DESC
LIMIT 15;
SQL

echo ""
echo "=== RECENT ALERTS ==="
$DDB <<SQL
SELECT
    severity,
    title,
    domain,
    client,
    analyzer
FROM alerts
WHERE timestamp > NOW() - INTERVAL '${WINDOW} minutes'
ORDER BY timestamp DESC
LIMIT 20;
SQL

echo ""
echo "=== NEW (UNBASELINED) DOMAINS ==="
$DDB <<SQL
SELECT COUNT(DISTINCT d.domain) AS new_domains
FROM dns_events d
LEFT JOIN domain_baseline b
    ON d.domain = b.domain AND d.client = b.client
WHERE d.timestamp > NOW() - INTERVAL '${WINDOW} minutes'
  AND b.domain IS NULL;
SQL

echo ""
echo "=== TABLE STATS ==="
$DDB <<SQL
SELECT 'dns_events' AS tbl, COUNT(*) AS rows,
       MIN(timestamp)::DATE AS oldest, MAX(timestamp)::DATE AS newest
FROM dns_events
UNION ALL
SELECT 'alerts', COUNT(*), MIN(timestamp)::DATE, MAX(timestamp)::DATE
FROM alerts
UNION ALL
SELECT 'connection_events', COUNT(*), MIN(timestamp)::DATE, MAX(timestamp)::DATE
FROM connection_events
UNION ALL
SELECT 'domain_baseline', COUNT(*), NULL, NULL
FROM domain_baseline
UNION ALL
SELECT 'device_activity_baseline', COUNT(*), NULL, NULL
FROM device_activity_baseline
UNION ALL
SELECT 'volume_baseline', COUNT(*), NULL, NULL
FROM volume_baseline
UNION ALL
SELECT 'watchdog_observations', COUNT(*), MIN(timestamp)::DATE, MAX(timestamp)::DATE
FROM watchdog_observations;
SQL
