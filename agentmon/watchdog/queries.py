"""DuckDB queries for watchdog traffic snapshots.

Short-window queries that power the OODA Observe phase.
All functions operate on a DuckDB connection directly.
"""

from datetime import UTC, datetime, timedelta

import duckdb


def get_recent_activity_snapshot(
    conn: duckdb.DuckDBPyConnection,
    window_minutes: int = 30,
) -> dict:
    """Get aggregate traffic stats for the recent window.

    Returns:
        Dict with total_queries, unique_domains, blocked_count.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = conn.execute("""
        SELECT
            COUNT(*) as total_queries,
            COUNT(DISTINCT domain) as unique_domains,
            SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count
        FROM dns_events
        WHERE timestamp > ?
    """, [cutoff]).fetchone()

    if result is None:
        return {"total_queries": 0, "unique_domains": 0, "blocked_count": 0}

    return {
        "total_queries": result[0] or 0,
        "unique_domains": result[1] or 0,
        "blocked_count": result[2] or 0,
    }


def get_top_clients_recent(
    conn: duckdb.DuckDBPyConnection,
    window_minutes: int = 30,
    limit: int = 10,
) -> list[dict]:
    """Get top clients by query volume in the recent window.

    Returns:
        List of dicts with client, query_count, unique_domains.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = conn.execute("""
        SELECT
            client,
            COUNT(*) as query_count,
            COUNT(DISTINCT domain) as unique_domains
        FROM dns_events
        WHERE timestamp > ?
        GROUP BY client
        ORDER BY query_count DESC
        LIMIT ?
    """, [cutoff, limit]).fetchall()

    columns = ["client", "query_count", "unique_domains"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_top_domains_recent(
    conn: duckdb.DuckDBPyConnection,
    window_minutes: int = 30,
    limit: int = 15,
) -> list[dict]:
    """Get top domains by query volume in the recent window.

    Returns:
        List of dicts with domain, query_count, client_count, any_blocked.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = conn.execute("""
        SELECT
            domain,
            COUNT(*) as query_count,
            COUNT(DISTINCT client) as client_count,
            BOOL_OR(blocked) as any_blocked
        FROM dns_events
        WHERE timestamp > ?
        GROUP BY domain
        ORDER BY query_count DESC
        LIMIT ?
    """, [cutoff, limit]).fetchall()

    columns = ["domain", "query_count", "client_count", "any_blocked"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_recent_alerts_summary(
    conn: duckdb.DuckDBPyConnection,
    window_minutes: int = 30,
    limit: int = 20,
) -> list[dict]:
    """Get recent alerts within the window.

    Returns:
        List of dicts with severity, title, domain, client, analyzer.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = conn.execute("""
        SELECT
            severity,
            title,
            domain,
            client,
            analyzer
        FROM alerts
        WHERE timestamp > ?
        ORDER BY timestamp DESC
        LIMIT ?
    """, [cutoff, limit]).fetchall()

    columns = ["severity", "title", "domain", "client", "analyzer"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_new_domains_count(
    conn: duckdb.DuckDBPyConnection,
    window_minutes: int = 30,
) -> int:
    """Count domains seen in the window that are NOT in the baseline.

    Returns:
        Number of new (unbaselined) domains.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = conn.execute("""
        SELECT COUNT(DISTINCT d.domain)
        FROM dns_events d
        LEFT JOIN domain_baseline b
            ON d.domain = b.domain AND d.client = b.client
        WHERE d.timestamp > ?
          AND b.domain IS NULL
    """, [cutoff]).fetchone()

    return result[0] if result and result[0] else 0
