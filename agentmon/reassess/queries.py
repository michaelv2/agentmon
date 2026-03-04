"""Read-only DuckDB queries for reassessment analysis.

All functions operate on a read-only EventStore connection.
"""

from datetime import UTC, datetime, timedelta

import duckdb


def get_high_frequency_alert_domains(
    conn: duckdb.DuckDBPyConnection,
    days: int = 7,
    min_count: int = 5,
) -> list[dict]:
    """Get domains with many recent alerts — false positive candidates.

    Args:
        conn: DuckDB connection.
        days: Lookback window in days.
        min_count: Minimum alert count to include.

    Returns:
        List of dicts with domain, alert_count, fp_count, ack_count, severities.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = conn.execute("""
        SELECT
            domain,
            COUNT(*) as alert_count,
            SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as fp_count,
            SUM(CASE WHEN acknowledged THEN 1 ELSE 0 END) as ack_count,
            LIST(DISTINCT severity) as severities,
            LIST(DISTINCT analyzer) as analyzers
        FROM alerts
        WHERE domain IS NOT NULL
          AND domain != ''
          AND timestamp > ?
        GROUP BY domain
        HAVING COUNT(*) >= ?
        ORDER BY alert_count DESC
    """, [cutoff, min_count]).fetchall()

    columns = ["domain", "alert_count", "fp_count", "ack_count", "severities", "analyzers"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_unflagged_high_traffic_domains(
    conn: duckdb.DuckDBPyConnection,
    min_clients: int = 2,
) -> list[dict]:
    """Get multi-client domains that were never flagged — blind spot candidates.

    Args:
        conn: DuckDB connection.
        min_clients: Minimum distinct clients querying the domain.

    Returns:
        List of dicts with domain, client_count, total_queries.
    """
    result = conn.execute("""
        SELECT
            d.domain,
            COUNT(DISTINCT d.client) as client_count,
            COUNT(*) as total_queries
        FROM dns_events d
        LEFT JOIN alerts a ON d.domain = a.domain
        WHERE a.domain IS NULL
        GROUP BY d.domain
        HAVING COUNT(DISTINCT d.client) >= ?
        ORDER BY client_count DESC, total_queries DESC
        LIMIT 50
    """, [min_clients]).fetchall()

    columns = ["domain", "client_count", "total_queries"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_analyzer_false_positive_rates(
    conn: duckdb.DuckDBPyConnection,
    days: int = 30,
) -> list[dict]:
    """Get per-analyzer alert volume and false positive rate.

    Args:
        conn: DuckDB connection.
        days: Lookback window in days.

    Returns:
        List of dicts with analyzer, total_alerts, fp_count, fp_rate.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = conn.execute("""
        SELECT
            analyzer,
            COUNT(*) as total_alerts,
            SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as fp_count,
            ROUND(
                CAST(SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) AS DOUBLE)
                / NULLIF(COUNT(*), 0), 3
            ) as fp_rate
        FROM alerts
        WHERE analyzer IS NOT NULL
          AND analyzer != ''
          AND timestamp > ?
        GROUP BY analyzer
        ORDER BY total_alerts DESC
    """, [cutoff]).fetchall()

    columns = ["analyzer", "total_alerts", "fp_count", "fp_rate"]
    return [dict(zip(columns, row, strict=True)) for row in result]


def get_recent_alert_sample(
    conn: duckdb.DuckDBPyConnection,
    days: int = 7,
    limit: int = 100,
) -> list[dict]:
    """Get a sample of recent alerts for LLM context.

    Args:
        conn: DuckDB connection.
        days: Lookback window in days.
        limit: Maximum number of alerts to return.

    Returns:
        List of dicts with timestamp, severity, title, domain, analyzer, false_positive.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = conn.execute("""
        SELECT
            timestamp,
            severity,
            title,
            domain,
            client,
            analyzer,
            false_positive,
            acknowledged
        FROM alerts
        WHERE timestamp > ?
        ORDER BY timestamp DESC
        LIMIT ?
    """, [cutoff, limit]).fetchall()

    columns = [
        "timestamp", "severity", "title", "domain",
        "client", "analyzer", "false_positive", "acknowledged",
    ]
    return [dict(zip(columns, row, strict=True)) for row in result]
