"""DuckDB storage for agentmon events.

DuckDB is chosen for:
- Excellent analytical query performance
- Column-oriented storage (efficient for time-series)
- SQL interface (portable knowledge, easy Rust migration)
- Single-file database (simple deployment)
"""

import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import uuid

import duckdb

from agentmon.models import DNSEvent, ConnectionEvent, Alert, Severity


SCHEMA_VERSION = 2


class EventStore:
    """DuckDB-backed storage for network events and alerts."""

    def __init__(self, db_path: Path, read_only: bool = False) -> None:
        """Initialize the event store.

        Args:
            db_path: Path to the DuckDB database file. Use ":memory:" for in-memory.
            read_only: If True, open in read-only mode (allows concurrent readers).
        """
        self.db_path = db_path
        self.read_only = read_only
        self._conn: Optional[duckdb.DuckDBPyConnection] = None
        self._temp_db_path: Optional[Path] = None

    def connect(self) -> None:
        """Open database connection and ensure schema exists."""
        db_str = str(self.db_path) if self.db_path != Path(":memory:") else ":memory:"

        if self.read_only and self.db_path != Path(":memory:"):
            # For read-only access, copy DB to temp file to avoid lock conflicts
            # DuckDB doesn't support true concurrent read access with a writer
            try:
                self._conn = duckdb.connect(db_str, read_only=True)
            except duckdb.IOException:
                # Database is locked by writer, copy to temp file
                # Must copy both .db and .wal files for complete data
                import os
                temp_dir = tempfile.mkdtemp(prefix="agentmon_")
                self._temp_db_path = Path(temp_dir) / "events.db"
                shutil.copy2(self.db_path, self._temp_db_path)
                # Also copy WAL file if it exists
                wal_path = Path(str(self.db_path) + ".wal")
                if wal_path.exists():
                    shutil.copy2(wal_path, Path(temp_dir) / "events.db.wal")
                self._conn = duckdb.connect(str(self._temp_db_path), read_only=True)
        else:
            self._conn = duckdb.connect(db_str, read_only=self.read_only)

        if not self.read_only:
            self._ensure_schema()

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
        # Clean up temp directory if we created one
        if self._temp_db_path and self._temp_db_path.exists():
            temp_dir = self._temp_db_path.parent
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._temp_db_path = None

    def __enter__(self) -> "EventStore":
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        """Get the database connection, raising if not connected."""
        if self._conn is None:
            raise RuntimeError("EventStore not connected. Call connect() first.")
        return self._conn

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Check current version
        result = self.conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        current_version = result[0] if result and result[0] else 0

        if current_version < SCHEMA_VERSION:
            self._apply_schema()
            self.conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                [SCHEMA_VERSION]
            )

    def _apply_schema(self) -> None:
        """Apply the database schema."""
        # DNS events table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_events (
                id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                client VARCHAR NOT NULL,
                domain VARCHAR NOT NULL,
                query_type VARCHAR NOT NULL,
                blocked BOOLEAN NOT NULL,
                upstream VARCHAR,
                response_time_ms DOUBLE,

                -- Derived fields for efficient querying
                domain_tld VARCHAR,
                domain_registered VARCHAR,  -- e.g., "example.com" from "sub.example.com"

                -- Indexing hints
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Connection events table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS connection_events (
                id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                client VARCHAR NOT NULL,
                src_port INTEGER NOT NULL,
                dst_ip VARCHAR NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol VARCHAR NOT NULL,
                bytes_sent BIGINT DEFAULT 0,
                bytes_recv BIGINT DEFAULT 0,
                duration_seconds DOUBLE,
                dns_domain VARCHAR,  -- Correlated DNS lookup

                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Alerts table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                severity VARCHAR NOT NULL,
                title VARCHAR NOT NULL,
                description VARCHAR NOT NULL,
                source_event_type VARCHAR NOT NULL,
                source_event_id VARCHAR,
                client VARCHAR,
                domain VARCHAR,
                dst_ip VARCHAR,
                process_name VARCHAR,

                analyzer VARCHAR,
                confidence DOUBLE,
                llm_analysis VARCHAR,

                acknowledged BOOLEAN DEFAULT FALSE,
                false_positive BOOLEAN DEFAULT FALSE,
                notes VARCHAR DEFAULT '',
                tags VARCHAR[] DEFAULT [],

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Domain baseline table (for anomaly detection)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_baseline (
                client VARCHAR NOT NULL,
                domain VARCHAR NOT NULL,
                first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                query_count BIGINT DEFAULT 1,

                PRIMARY KEY (client, domain)
            )
        """)

        # Device activity baseline table (for activity anomaly detection)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_activity_baseline (
                client VARCHAR NOT NULL,
                day_of_week INTEGER NOT NULL,
                hour_of_day INTEGER NOT NULL,
                query_count INTEGER DEFAULT 0,
                active_count INTEGER DEFAULT 0,
                sample_count INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (client, day_of_week, hour_of_day)
            )
        """)

        # Create indexes for common queries
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_timestamp
            ON dns_events (timestamp)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_client_domain
            ON dns_events (client, domain)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_conn_timestamp
            ON connection_events (timestamp)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity_ack
            ON alerts (severity, acknowledged)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_device_activity_client
            ON device_activity_baseline (client)
        """)

    def insert_dns_event(self, event: DNSEvent) -> str:
        """Insert a DNS event and return its ID."""
        event_id = str(uuid.uuid4())

        # Extract domain parts for efficient querying
        parts = event.domain_parts()
        tld = parts[-1] if parts else ""
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else event.domain

        self.conn.execute("""
            INSERT INTO dns_events (
                id, timestamp, client, domain, query_type, blocked,
                upstream, response_time_ms, domain_tld, domain_registered
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            event_id,
            event.timestamp,
            event.client,
            event.domain,
            event.query_type,
            event.blocked,
            event.upstream,
            event.response_time_ms,
            tld,
            registered,
        ])

        return event_id

    def mark_domain_blocked(self, domain: str, max_age_seconds: int = 5) -> bool:
        """Mark the most recent query for a domain as blocked.

        Pi-hole logs blocks separately from queries:
          query[A] example.com from 192.168.1.100
          gravity blocked example.com is 0.0.0.0

        This method correlates them by updating the recent query.

        Args:
            domain: The domain that was blocked
            max_age_seconds: Only update queries within this time window

        Returns:
            True if a query was updated, False otherwise
        """
        # Use datetime arithmetic instead of f-string interpolation for safety
        cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        result = self.conn.execute("""
            UPDATE dns_events
            SET blocked = TRUE
            WHERE id = (
                SELECT id FROM dns_events
                WHERE domain = ?
                  AND blocked = FALSE
                  AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 1
            )
        """, [domain, cutoff_time])
        return result.rowcount > 0

    def insert_dns_events_batch(self, events: list[DNSEvent]) -> int:
        """Insert multiple DNS events efficiently. Returns count inserted."""
        if not events:
            return 0

        rows = []
        for event in events:
            parts = event.domain_parts()
            tld = parts[-1] if parts else ""
            registered = ".".join(parts[-2:]) if len(parts) >= 2 else event.domain

            rows.append((
                str(uuid.uuid4()),
                event.timestamp,
                event.client,
                event.domain,
                event.query_type,
                event.blocked,
                event.upstream,
                event.response_time_ms,
                tld,
                registered,
            ))

        self.conn.executemany("""
            INSERT INTO dns_events (
                id, timestamp, client, domain, query_type, blocked,
                upstream, response_time_ms, domain_tld, domain_registered
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

        return len(rows)

    def insert_alert(self, alert: Alert) -> str:
        """Insert an alert and return its ID."""
        self.conn.execute("""
            INSERT INTO alerts (
                id, timestamp, severity, title, description,
                source_event_type, source_event_id, client, domain,
                dst_ip, process_name, analyzer, confidence, llm_analysis,
                acknowledged, false_positive, notes, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            alert.id,
            alert.timestamp,
            alert.severity.value,
            alert.title,
            alert.description,
            alert.source_event_type,
            alert.source_event_id,
            alert.client,
            alert.domain,
            alert.dst_ip,
            alert.process_name,
            alert.analyzer,
            alert.confidence,
            alert.llm_analysis,
            alert.acknowledged,
            alert.false_positive,
            alert.notes,
            alert.tags,
        ])

        return alert.id

    def update_domain_baseline(self, client: str, domain: str, timestamp: datetime) -> None:
        """Update the domain baseline for a client."""
        self.conn.execute("""
            INSERT INTO domain_baseline (client, domain, first_seen, last_seen, query_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT (client, domain) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                query_count = domain_baseline.query_count + 1
        """, [client, domain, timestamp, timestamp])

    def is_domain_known(self, client: str, domain: str) -> bool:
        """Check if a domain is in the baseline for a client."""
        result = self.conn.execute("""
            SELECT 1 FROM domain_baseline
            WHERE client = ? AND domain = ?
            LIMIT 1
        """, [client, domain]).fetchone()
        return result is not None

    def get_domain_first_seen(
        self, client: str, domain: str
    ) -> Optional[datetime]:
        """Get when a domain was first seen for a client."""
        result = self.conn.execute("""
            SELECT first_seen FROM domain_baseline
            WHERE client = ? AND domain = ?
        """, [client, domain]).fetchone()
        return result[0] if result else None

    def get_unacknowledged_alerts(
        self,
        min_severity: Severity = Severity.LOW,
        limit: int = 100
    ) -> list[dict]:
        """Get unacknowledged alerts at or above a severity level."""
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        min_level = severity_order[min_severity]

        # Filter in Python since DuckDB doesn't know our severity ordering
        result = self.conn.execute("""
            SELECT * FROM alerts
            WHERE acknowledged = FALSE AND false_positive = FALSE
            ORDER BY created_at DESC
            LIMIT ?
        """, [limit * 2]).fetchall()  # Fetch extra, filter in Python

        columns = [desc[0] for desc in self.conn.description]
        alerts = []
        for row in result:
            alert_dict = dict(zip(columns, row))
            alert_severity = Severity(alert_dict["severity"])
            if severity_order[alert_severity] >= min_level:
                alerts.append(alert_dict)
                if len(alerts) >= limit:
                    break

        return alerts

    def get_client_stats(self, hours: int = 24) -> list[dict]:
        """Get DNS query statistics per client for the last N hours."""
        # Use datetime arithmetic instead of f-string interpolation for safety
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        result = self.conn.execute("""
            SELECT
                client,
                COUNT(*) as total_queries,
                COUNT(DISTINCT domain) as unique_domains,
                SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_queries,
                MIN(timestamp) as first_query,
                MAX(timestamp) as last_query
            FROM dns_events
            WHERE timestamp > ?
            GROUP BY client
            ORDER BY total_queries DESC
        """, [cutoff_time]).fetchall()

        columns = ["client", "total_queries", "unique_domains",
                   "blocked_queries", "first_query", "last_query"]
        return [dict(zip(columns, row)) for row in result]

    # =========================================================================
    # Device Activity Baseline Methods
    # =========================================================================

    def update_device_activity(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        query_count: int,
        was_active: bool,
    ) -> None:
        """Update activity baseline for a device at a specific time slot.

        Args:
            client: Device IP address
            day_of_week: 0=Monday through 6=Sunday
            hour_of_day: 0-23
            query_count: Number of queries in this hour
            was_active: Whether the device exceeded the activity threshold
        """
        active_increment = 1 if was_active else 0
        now = datetime.now(timezone.utc)
        self.conn.execute("""
            INSERT INTO device_activity_baseline
                (client, day_of_week, hour_of_day, query_count, active_count, sample_count, last_updated)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT (client, day_of_week, hour_of_day) DO UPDATE SET
                query_count = device_activity_baseline.query_count + EXCLUDED.query_count,
                active_count = device_activity_baseline.active_count + ?,
                sample_count = device_activity_baseline.sample_count + 1,
                last_updated = ?
        """, [client, day_of_week, hour_of_day, query_count, active_increment, now, active_increment, now])

    def get_device_activity_baseline(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
    ) -> Optional[dict]:
        """Get baseline for a specific time slot.

        Args:
            client: Device IP address
            day_of_week: 0=Monday through 6=Sunday
            hour_of_day: 0-23

        Returns:
            Dict with query_count, active_count, sample_count, or None if no data
        """
        result = self.conn.execute("""
            SELECT query_count, active_count, sample_count, last_updated
            FROM device_activity_baseline
            WHERE client = ? AND day_of_week = ? AND hour_of_day = ?
        """, [client, day_of_week, hour_of_day]).fetchone()

        if result is None:
            return None

        return {
            "query_count": result[0],
            "active_count": result[1],
            "sample_count": result[2],
            "last_updated": result[3],
        }

    def get_device_first_activity(self, client: str) -> Optional[datetime]:
        """Get when a device was first observed (earliest last_updated).

        Used to determine if the device has passed the learning period.
        """
        result = self.conn.execute("""
            SELECT MIN(last_updated) FROM device_activity_baseline
            WHERE client = ?
        """, [client]).fetchone()
        return result[0] if result and result[0] else None

    def is_device_activity_anomalous(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        min_samples: int = 7,
    ) -> tuple[bool, float]:
        """Check if current activity is anomalous for this time slot.

        An anomaly is detected when the device is active during a time slot
        where it's historically rarely active (low active_ratio).

        Args:
            client: Device IP address
            day_of_week: 0=Monday through 6=Sunday
            hour_of_day: 0-23
            min_samples: Minimum observations required before detecting anomalies

        Returns:
            Tuple of (is_anomaly, active_ratio) where active_ratio is how often
            this device is active during this time slot (0.0 to 1.0).
            Returns (False, 0.0) if insufficient data.
        """
        baseline = self.get_device_activity_baseline(client, day_of_week, hour_of_day)

        if baseline is None or baseline["sample_count"] < min_samples:
            # Not enough data to determine anomaly
            return (False, 0.0)

        active_ratio = baseline["active_count"] / baseline["sample_count"]

        # If device is rarely active (<10% of the time) in this slot,
        # and it's now active, that's anomalous
        if active_ratio < 0.1:
            return (True, active_ratio)

        return (False, active_ratio)

    def get_device_activity_summary(self, client: str) -> dict:
        """Get a summary of a device's activity patterns.

        Returns:
            Dict with total_samples, active_hours (list of typically active hours),
            and inactive_hours (list of typically inactive hours).
        """
        result = self.conn.execute("""
            SELECT day_of_week, hour_of_day, active_count, sample_count
            FROM device_activity_baseline
            WHERE client = ?
            ORDER BY day_of_week, hour_of_day
        """, [client]).fetchall()

        if not result:
            return {"total_samples": 0, "active_hours": [], "inactive_hours": []}

        total_samples = sum(row[3] for row in result)
        active_hours = []
        inactive_hours = []

        for day, hour, active_count, sample_count in result:
            if sample_count >= 7:  # Minimum samples for reliable ratio
                ratio = active_count / sample_count
                slot = {"day": day, "hour": hour, "ratio": ratio}
                if ratio >= 0.5:
                    active_hours.append(slot)
                elif ratio < 0.1:
                    inactive_hours.append(slot)

        return {
            "total_samples": total_samples,
            "active_hours": active_hours,
            "inactive_hours": inactive_hours,
        }
