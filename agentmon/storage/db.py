"""DuckDB storage for agentmon events.

DuckDB is chosen for:
- Excellent analytical query performance
- Column-oriented storage (efficient for time-series)
- SQL interface (portable knowledge, easy Rust migration)
- Single-file database (simple deployment)
"""

import contextlib
import os
import shutil
import stat
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

from agentmon.models import Alert, ConnectionEvent, DNSEvent, Severity

SCHEMA_VERSION = 4


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
        self._conn: duckdb.DuckDBPyConnection | None = None
        self._temp_db_path: Path | None = None

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
                temp_dir = tempfile.mkdtemp(prefix="agentmon_")
                self._temp_db_path = Path(temp_dir) / "events.db"
                shutil.copy2(self.db_path, self._temp_db_path)
                # Secure temp copy permissions
                self._set_secure_permissions(self._temp_db_path)
                # Also copy WAL file if it exists
                wal_path = Path(str(self.db_path) + ".wal")
                if wal_path.exists():
                    temp_wal = Path(temp_dir) / "events.db.wal"
                    shutil.copy2(wal_path, temp_wal)
                    self._set_secure_permissions(temp_wal)
                self._conn = duckdb.connect(str(self._temp_db_path), read_only=True)
        else:
            self._conn = duckdb.connect(db_str, read_only=self.read_only)

        if not self.read_only:
            self._ensure_schema()
            # Secure the database file after creation
            if self.db_path != Path(":memory:") and self.db_path.exists():
                self._set_secure_permissions(self.db_path)

    @staticmethod
    def _set_secure_permissions(path: Path) -> None:
        """Set file permissions to owner-only (0o600)."""
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

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

        # Volume baseline table (Welford's online algorithm for running stats)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS volume_baseline (
                client VARCHAR NOT NULL,
                day_of_week INTEGER NOT NULL,
                hour_of_day INTEGER NOT NULL,
                query_count_mean DOUBLE DEFAULT 0.0,
                query_count_m2 DOUBLE DEFAULT 0.0,
                domain_count_mean DOUBLE DEFAULT 0.0,
                domain_count_m2 DOUBLE DEFAULT 0.0,
                sample_count INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (client, day_of_week, hour_of_day)
            )
        """)

        # Watchdog observations audit trail
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS watchdog_observations (
                id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                cycle_number INTEGER NOT NULL,
                snapshot_json VARCHAR NOT NULL,
                concerns_json VARCHAR NOT NULL,
                action_taken VARCHAR NOT NULL,
                api_latency_ms DOUBLE,
                input_tokens INTEGER,
                output_tokens INTEGER,
                estimated_cost_usd DOUBLE,
                model_used VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Pending tune actions (human approval gate for OODA watchdog)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_tune_actions (
                id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                cycle_number INTEGER NOT NULL,
                tune_action VARCHAR NOT NULL,
                tune_value VARCHAR NOT NULL,
                concern_title VARCHAR NOT NULL,
                concern_description VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                confidence DOUBLE NOT NULL,
                status VARCHAR NOT NULL DEFAULT 'pending',
                reviewed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_volume_baseline_client
            ON volume_baseline (client)
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
        cutoff_time = datetime.now(UTC) - timedelta(seconds=max_age_seconds)
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

    def insert_connection_event(self, event: ConnectionEvent) -> str:
        """Insert a connection event and return its ID."""
        event_id = str(uuid.uuid4())

        self.conn.execute("""
            INSERT INTO connection_events (
                id, timestamp, client, src_port, dst_ip, dst_port,
                protocol, bytes_sent, bytes_recv, duration_seconds, dns_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            event_id,
            event.timestamp,
            event.client,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.protocol,
            event.bytes_sent,
            event.bytes_recv,
            event.duration_seconds,
            event.dns_domain,
        ])

        return event_id

    def insert_connection_events_batch(self, events: list[ConnectionEvent]) -> int:
        """Insert multiple connection events efficiently. Returns count inserted."""
        if not events:
            return 0

        rows = []
        for event in events:
            rows.append((
                str(uuid.uuid4()),
                event.timestamp,
                event.client,
                event.src_port,
                event.dst_ip,
                event.dst_port,
                event.protocol,
                event.bytes_sent,
                event.bytes_recv,
                event.duration_seconds,
                event.dns_domain,
            ))

        self.conn.executemany("""
            INSERT INTO connection_events (
                id, timestamp, client, src_port, dst_ip, dst_port,
                protocol, bytes_sent, bytes_recv, duration_seconds, dns_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def get_domain_popularity(self, domain: str) -> tuple[int, int]:
        """Get total query count and unique client count for a domain.

        Uses the domain_baseline table (cumulative counts) to determine
        how well-established a domain is across all clients.

        Returns:
            Tuple of (total_queries, unique_clients).
        """
        result = self.conn.execute("""
            SELECT COALESCE(SUM(query_count), 0), COUNT(DISTINCT client)
            FROM domain_baseline
            WHERE domain = ?
        """, [domain]).fetchone()
        return (result[0], result[1]) if result else (0, 0)

    def get_domain_first_seen(
        self, client: str, domain: str
    ) -> datetime | None:
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
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)
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
        now = datetime.now(UTC)
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
    ) -> dict | None:
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

    def get_device_first_activity(self, client: str) -> datetime | None:
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

    # =========================================================================
    # Volume Baseline Methods (Welford's Online Algorithm)
    # =========================================================================

    def update_volume_baseline(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        query_count: int,
        domain_count: int,
    ) -> None:
        """Update volume baseline using Welford's online algorithm.

        Maintains running mean and M2 (sum of squared deviations) for both
        query count and domain count, enabling O(1) variance computation.

        Args:
            client: Device IP or hostname.
            day_of_week: 0=Monday through 6=Sunday.
            hour_of_day: 0-23.
            query_count: Number of queries observed this hour.
            domain_count: Number of unique domains observed this hour.
        """
        now = datetime.now(UTC)
        existing = self.get_volume_baseline(client, day_of_week, hour_of_day)

        if existing is None:
            # First observation: mean = value, M2 = 0, n = 1
            self.conn.execute("""
                INSERT INTO volume_baseline (
                    client, day_of_week, hour_of_day,
                    query_count_mean, query_count_m2,
                    domain_count_mean, domain_count_m2,
                    sample_count, last_updated
                ) VALUES (?, ?, ?, ?, 0.0, ?, 0.0, 1, ?)
            """, [client, day_of_week, hour_of_day,
                  float(query_count), float(domain_count), now])
        else:
            n = existing["sample_count"] + 1

            # Welford update for query_count
            q_delta = query_count - existing["query_count_mean"]
            q_new_mean = existing["query_count_mean"] + q_delta / n
            q_delta2 = query_count - q_new_mean
            q_new_m2 = existing["query_count_m2"] + q_delta * q_delta2

            # Welford update for domain_count
            d_delta = domain_count - existing["domain_count_mean"]
            d_new_mean = existing["domain_count_mean"] + d_delta / n
            d_delta2 = domain_count - d_new_mean
            d_new_m2 = existing["domain_count_m2"] + d_delta * d_delta2

            self.conn.execute("""
                UPDATE volume_baseline SET
                    query_count_mean = ?,
                    query_count_m2 = ?,
                    domain_count_mean = ?,
                    domain_count_m2 = ?,
                    sample_count = ?,
                    last_updated = ?
                WHERE client = ? AND day_of_week = ? AND hour_of_day = ?
            """, [q_new_mean, q_new_m2, d_new_mean, d_new_m2,
                  n, now, client, day_of_week, hour_of_day])

    def get_volume_baseline(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
    ) -> dict | None:
        """Get volume baseline for a specific time slot.

        Returns:
            Dict with query_count_mean, query_count_m2, domain_count_mean,
            domain_count_m2, sample_count, last_updated, or None.
        """
        result = self.conn.execute("""
            SELECT query_count_mean, query_count_m2,
                   domain_count_mean, domain_count_m2,
                   sample_count, last_updated
            FROM volume_baseline
            WHERE client = ? AND day_of_week = ? AND hour_of_day = ?
        """, [client, day_of_week, hour_of_day]).fetchone()

        if result is None:
            return None

        return {
            "query_count_mean": result[0],
            "query_count_m2": result[1],
            "domain_count_mean": result[2],
            "domain_count_m2": result[3],
            "sample_count": result[4],
            "last_updated": result[5],
        }

    def is_volume_anomalous(
        self,
        client: str,
        day_of_week: int,
        hour_of_day: int,
        value: float,
        metric: str = "query_count",
        sigma: float = 3.0,
        min_samples: int = 7,
    ) -> tuple[bool, float]:
        """Check if a volume metric is anomalously high using z-score.

        Uses Welford's stored M2 to compute variance = M2 / (n - 1),
        then z = (value - mean) / stddev. Anomaly if z > sigma.

        Args:
            client: Device IP or hostname.
            day_of_week: 0=Monday through 6=Sunday.
            hour_of_day: 0-23.
            value: Observed value to check.
            metric: "query_count" or "domain_count".
            sigma: Z-score threshold for anomaly detection.
            min_samples: Minimum observations before detecting anomalies.

        Returns:
            Tuple of (is_anomaly, z_score). Returns (False, 0.0) if
            insufficient data.
        """
        baseline = self.get_volume_baseline(client, day_of_week, hour_of_day)

        if baseline is None or baseline["sample_count"] < min_samples:
            return (False, 0.0)

        mean = baseline[f"{metric}_mean"]
        m2 = baseline[f"{metric}_m2"]
        n = baseline["sample_count"]

        if n < 2:
            return (False, 0.0)

        variance = m2 / (n - 1)

        import math

        if variance <= 0 or m2 <= 0:
            # Zero variance: all observations were identical.
            # If value exceeds mean, treat as infinite z-score.
            if value > mean:
                return (True, float("inf"))
            return (False, 0.0)

        stddev = math.sqrt(variance)
        z_score = (value - mean) / stddev

        return (z_score > sigma, z_score)

    def get_volume_first_observation(self, client: str) -> datetime | None:
        """Get when a device was first observed in volume baseline.

        Used to determine if the device has passed the learning period.
        """
        result = self.conn.execute("""
            SELECT MIN(last_updated) FROM volume_baseline
            WHERE client = ?
        """, [client]).fetchone()
        return result[0] if result and result[0] else None

    def insert_watchdog_observation(
        self,
        observation_id: str,
        timestamp: datetime,
        cycle_number: int,
        snapshot_json: str,
        concerns_json: str,
        action_taken: str,
        api_latency_ms: float | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        estimated_cost_usd: float | None = None,
        model_used: str | None = None,
    ) -> None:
        """Insert a watchdog observation audit record."""
        self.conn.execute("""
            INSERT INTO watchdog_observations (
                id, timestamp, cycle_number, snapshot_json, concerns_json,
                action_taken, api_latency_ms, input_tokens, output_tokens,
                estimated_cost_usd, model_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            observation_id, timestamp, cycle_number, snapshot_json,
            concerns_json, action_taken, api_latency_ms, input_tokens,
            output_tokens, estimated_cost_usd, model_used,
        ])

    # =========================================================================
    # Pending Tune Action Methods
    # =========================================================================

    def insert_pending_tune(self, action: dict) -> str:
        """Insert a pending tune action.

        Args:
            action: Dict with id, timestamp, cycle_number, tune_action,
                tune_value, concern_title, concern_description, severity,
                confidence, status.

        Returns:
            The tune action ID.
        """
        self.conn.execute("""
            INSERT INTO pending_tune_actions (
                id, timestamp, cycle_number, tune_action, tune_value,
                concern_title, concern_description, severity, confidence, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            action["id"],
            action["timestamp"],
            action["cycle_number"],
            action["tune_action"],
            action["tune_value"],
            action["concern_title"],
            action["concern_description"],
            action["severity"],
            action["confidence"],
            action.get("status", "pending"),
        ])
        return action["id"]

    def get_pending_tunes(self, status: str = "pending") -> list[dict]:
        """Get pending tune actions filtered by status.

        Args:
            status: Filter by status ("pending", "approved", "rejected").

        Returns:
            List of dicts with tune action details.
        """
        result = self.conn.execute("""
            SELECT id, timestamp, cycle_number, tune_action, tune_value,
                   concern_title, concern_description, severity, confidence,
                   status, reviewed_at, created_at
            FROM pending_tune_actions
            WHERE status = ?
            ORDER BY created_at DESC
        """, [status]).fetchall()

        columns = [
            "id", "timestamp", "cycle_number", "tune_action", "tune_value",
            "concern_title", "concern_description", "severity", "confidence",
            "status", "reviewed_at", "created_at",
        ]
        return [dict(zip(columns, row, strict=True)) for row in result]

    def update_pending_tune_status(self, tune_id: str, status: str) -> bool:
        """Update the status of a pending tune action.

        Args:
            tune_id: The tune action ID.
            status: New status ("approved" or "rejected").

        Returns:
            True if the tune action was found and updated.
        """
        count_row = self.conn.execute(
            "SELECT COUNT(*) FROM pending_tune_actions WHERE id = ?",
            [tune_id],
        ).fetchone()
        count: int = count_row[0] if count_row else 0

        if count == 0:
            return False

        self.conn.execute("""
            UPDATE pending_tune_actions
            SET status = ?, reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, [status, tune_id])
        return True

    # =========================================================================
    # Data Retention / Cleanup Methods
    # =========================================================================

    def cleanup_old_data(
        self,
        dns_events_days: int = 30,
        alerts_days: int = 90,
        connection_events_days: int | None = None,
    ) -> dict[str, int]:
        """Delete data older than retention periods.

        Args:
            dns_events_days: Delete DNS events older than this many days
            alerts_days: Delete alerts older than this many days
            connection_events_days: Delete connection events older than this many days
                (defaults to dns_events_days if None)

        Returns:
            Dict with counts of deleted records
        """
        conn_days = connection_events_days if connection_events_days is not None else dns_events_days

        dns_cutoff = datetime.now(UTC) - timedelta(days=dns_events_days)
        alerts_cutoff = datetime.now(UTC) - timedelta(days=alerts_days)
        conn_cutoff = datetime.now(UTC) - timedelta(days=conn_days)

        # DuckDB DELETE doesn't reliably return rowcount, so count first
        dns_row = self.conn.execute(
            "SELECT COUNT(*) FROM dns_events WHERE timestamp < ?", [dns_cutoff]
        ).fetchone()
        dns_deleted: int = dns_row[0] if dns_row else 0
        self.conn.execute("DELETE FROM dns_events WHERE timestamp < ?", [dns_cutoff])

        alerts_row = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp < ?", [alerts_cutoff]
        ).fetchone()
        alerts_deleted: int = alerts_row[0] if alerts_row else 0
        self.conn.execute("DELETE FROM alerts WHERE timestamp < ?", [alerts_cutoff])

        conn_row = self.conn.execute(
            "SELECT COUNT(*) FROM connection_events WHERE timestamp < ?", [conn_cutoff]
        ).fetchone()
        conn_deleted: int = conn_row[0] if conn_row else 0
        self.conn.execute(
            "DELETE FROM connection_events WHERE timestamp < ?", [conn_cutoff]
        )

        return {
            "dns_events_deleted": dns_deleted,
            "alerts_deleted": alerts_deleted,
            "connection_events_deleted": conn_deleted,
        }

    def vacuum(self) -> None:
        """Reclaim disk space after deletions."""
        self.conn.execute("VACUUM")

    # =========================================================================
    # Alert Review / Dashboard Methods
    # =========================================================================

    def get_flagged_domains_summary(
        self,
        limit: int = 100,
        min_severity: str | None = None,
    ) -> list[dict]:
        """Get aggregated summary of flagged domains from alerts.

        Groups alerts by domain, returning alert counts, severity breakdown,
        and which analyzers flagged each domain. Results are sorted by max
        severity (highest first), then by alert count.

        Args:
            limit: Maximum number of domains to return.
            min_severity: If set, only include alerts at or above this severity
                (info, low, medium, high, critical).

        Returns:
            List of dicts with domain, alert_count, max_severity, severities,
            analyzers, first_seen, last_seen, acknowledged_count,
            false_positive_count.
        """
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        where_clause = "WHERE domain IS NOT NULL AND domain != ''"
        params: list[object] = []

        if min_severity and min_severity in severity_order:
            threshold = severity_order[min_severity]
            allowed = [s for s, v in severity_order.items() if v >= threshold]
            placeholders = ", ".join("?" for _ in allowed)
            where_clause += f" AND severity IN ({placeholders})"
            params.extend(allowed)

        params.append(limit)

        result = self.conn.execute(f"""
            SELECT
                domain,
                COUNT(*) as alert_count,
                MAX(CASE severity
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END) as max_severity_rank,
                LIST(DISTINCT severity) as severities,
                LIST(DISTINCT analyzer) as analyzers,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                SUM(CASE WHEN acknowledged THEN 1 ELSE 0 END) as acknowledged_count,
                SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as false_positive_count
            FROM alerts
            {where_clause}
            GROUP BY domain
            ORDER BY max_severity_rank DESC, alert_count DESC
            LIMIT ?
        """, params).fetchall()

        rank_to_name = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        columns = [
            "domain", "alert_count", "max_severity_rank", "severities", "analyzers",
            "first_seen", "last_seen", "acknowledged_count", "false_positive_count",
        ]
        rows = [dict(zip(columns, row, strict=True)) for row in result]
        for row in rows:
            row["max_severity"] = rank_to_name.get(row.pop("max_severity_rank"), "info")
        return rows

    def get_domain_querying_clients(self, domain: str) -> list[dict]:
        """Get clients that queried a specific domain.

        Returns:
            List of dicts with client, query_count, first_query, last_query.
        """
        result = self.conn.execute("""
            SELECT
                client,
                COUNT(*) as query_count,
                MIN(timestamp) as first_query,
                MAX(timestamp) as last_query
            FROM dns_events
            WHERE domain = ?
            GROUP BY client
            ORDER BY query_count DESC
        """, [domain]).fetchall()

        columns = ["client", "query_count", "first_query", "last_query"]
        return [dict(zip(columns, row, strict=True)) for row in result]

    def acknowledge_domain_alerts(self, domain: str) -> int:
        """Mark all alerts for a domain as acknowledged.

        Returns:
            Number of alerts updated.
        """
        count_row = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE domain = ? AND acknowledged = FALSE",
            [domain],
        ).fetchone()
        count: int = count_row[0] if count_row else 0

        if count > 0:
            self.conn.execute(
                "UPDATE alerts SET acknowledged = TRUE WHERE domain = ? AND acknowledged = FALSE",
                [domain],
            )
        return count

    def mark_domain_false_positive(self, domain: str) -> int:
        """Mark all alerts for a domain as false positives.

        Returns:
            Number of alerts updated.
        """
        count_row = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE domain = ? AND false_positive = FALSE",
            [domain],
        ).fetchone()
        count: int = count_row[0] if count_row else 0

        if count > 0:
            self.conn.execute(
                "UPDATE alerts SET false_positive = TRUE "
                "WHERE domain = ? AND false_positive = FALSE",
                [domain],
            )
        return count

    # =========================================================================
    # Table Statistics
    # =========================================================================

    def get_table_stats(self) -> dict[str, dict]:
        """Get row counts and date ranges for main tables.

        Returns:
            Dict with table names as keys, containing count, oldest, and newest dates.
        """
        stats = {}

        # DNS events
        result = self.conn.execute("""
            SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
            FROM dns_events
        """).fetchone()
        stats["dns_events"] = {
            "count": result[0] if result else 0,
            "oldest": result[1] if result else None,
            "newest": result[2] if result else None,
        }

        # Alerts
        result = self.conn.execute("""
            SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
            FROM alerts
        """).fetchone()
        stats["alerts"] = {
            "count": result[0] if result else 0,
            "oldest": result[1] if result else None,
            "newest": result[2] if result else None,
        }

        # Connection events
        result = self.conn.execute("""
            SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
            FROM connection_events
        """).fetchone()
        stats["connection_events"] = {
            "count": result[0] if result else 0,
            "oldest": result[1] if result else None,
            "newest": result[2] if result else None,
        }

        # Domain baseline (bounded, no date range)
        result = self.conn.execute("""
            SELECT COUNT(*) FROM domain_baseline
        """).fetchone()
        stats["domain_baseline"] = {
            "count": result[0] if result else 0,
        }

        # Device activity baseline (bounded, no date range)
        result = self.conn.execute("""
            SELECT COUNT(*) FROM device_activity_baseline
        """).fetchone()
        stats["device_activity_baseline"] = {
            "count": result[0] if result else 0,
        }

        # Volume baseline (bounded, no date range)
        result = self.conn.execute("""
            SELECT COUNT(*) FROM volume_baseline
        """).fetchone()
        stats["volume_baseline"] = {
            "count": result[0] if result else 0,
        }

        # Watchdog observations
        result = self.conn.execute("""
            SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
            FROM watchdog_observations
        """).fetchone()
        stats["watchdog_observations"] = {
            "count": result[0] if result else 0,
            "oldest": result[1] if result else None,
            "newest": result[2] if result else None,
        }

        return stats
