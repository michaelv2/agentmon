"""Pi-hole DNS log collector.

Supports two collection methods:
1. Direct SQLite access to pihole-FTL.db (local or via SSH mount)
2. SSH + sqlite3 CLI for remote queries without mounting
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from agentmon.models import DNSEvent


@dataclass
class PiholeConfig:
    """Configuration for Pi-hole collector."""

    # Local path to FTL database (if accessible)
    db_path: Optional[Path] = None

    # SSH connection details (if remote)
    ssh_host: Optional[str] = None
    ssh_user: str = "pi"
    ssh_key_path: Optional[Path] = None
    remote_db_path: str = "/etc/pihole/pihole-FTL.db"

    # Collection settings
    batch_size: int = 1000
    query_types_to_collect: frozenset[str] = frozenset({"A", "AAAA", "CNAME", "MX", "TXT"})


# Pi-hole FTL query type mapping
# See: https://docs.pi-hole.net/database/ftl/
QUERY_TYPE_MAP: dict[int, str] = {
    1: "A",
    2: "AAAA",
    3: "ANY",
    4: "SRV",
    5: "SOA",
    6: "PTR",
    7: "TXT",
    8: "NAPTR",
    9: "MX",
    10: "DS",
    11: "RRSIG",
    12: "DNSKEY",
    13: "NS",
    14: "SVCB",
    15: "HTTPS",
}

# Pi-hole status codes
STATUS_BLOCKED_CODES = {1, 4, 5, 6, 7, 8, 9, 10, 11}  # Various block reasons


class PiholeCollector:
    """Collects DNS events from Pi-hole's FTL database."""

    def __init__(self, config: PiholeConfig) -> None:
        self.config = config
        self._last_timestamp: Optional[float] = None

    def collect_local(self, since: Optional[datetime] = None) -> Iterator[DNSEvent]:
        """Collect events from a locally accessible FTL database."""
        if self.config.db_path is None:
            raise ValueError("db_path must be set for local collection")

        if not self.config.db_path.exists():
            raise FileNotFoundError(f"Pi-hole database not found: {self.config.db_path}")

        # Connect read-only to avoid interfering with Pi-hole
        conn = sqlite3.connect(f"file:{self.config.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        try:
            yield from self._query_events(conn, since)
        finally:
            conn.close()

    def collect_remote_ssh(self, since: Optional[datetime] = None) -> Iterator[DNSEvent]:
        """Collect events via SSH from a remote Pi-hole.

        This method SSHs to the Pi-hole and runs sqlite3 queries remotely,
        avoiding the need to mount the database file.
        """
        # Import here to avoid hard dependency if not using SSH
        import paramiko

        if self.config.ssh_host is None:
            raise ValueError("ssh_host must be set for remote collection")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.config.ssh_host,
            "username": self.config.ssh_user,
        }
        if self.config.ssh_key_path:
            connect_kwargs["key_filename"] = str(self.config.ssh_key_path)

        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
            yield from self._query_events_ssh(client, since)
        finally:
            client.close()

    def _query_events(
        self, conn: sqlite3.Connection, since: Optional[datetime]
    ) -> Iterator[DNSEvent]:
        """Query events from a SQLite connection."""
        cursor = conn.cursor()

        # Build query with optional timestamp filter
        query = """
            SELECT
                timestamp,
                client,
                domain,
                type,
                status,
                reply_time
            FROM queries
            WHERE 1=1
        """
        params: list[object] = []

        if since is not None:
            query += " AND timestamp > ?"
            params.append(since.timestamp())

        query += " ORDER BY timestamp ASC LIMIT ?"
        params.append(self.config.batch_size)

        cursor.execute(query, params)

        for row in cursor:
            event = self._row_to_event(row)
            if event is not None:
                self._last_timestamp = row["timestamp"]
                yield event

    def _query_events_ssh(
        self,
        client: "paramiko.SSHClient",
        since: Optional[datetime],
    ) -> Iterator[DNSEvent]:
        """Query events via SSH using sqlite3 CLI."""
        # Build the sqlite3 command
        where_clause = ""
        if since is not None:
            where_clause = f"WHERE timestamp > {since.timestamp()}"

        sql = f"""
            SELECT timestamp, client, domain, type, status, reply_time
            FROM queries
            {where_clause}
            ORDER BY timestamp ASC
            LIMIT {self.config.batch_size};
        """

        cmd = f'sqlite3 -separator "|" "{self.config.remote_db_path}" "{sql}"'

        _, stdout, stderr = client.exec_command(cmd)

        error = stderr.read().decode().strip()
        if error:
            raise RuntimeError(f"SSH sqlite3 query failed: {error}")

        for line in stdout:
            parts = line.strip().split("|")
            if len(parts) >= 6:
                event = self._parse_ssh_row(parts)
                if event is not None:
                    yield event

    def _row_to_event(self, row: sqlite3.Row) -> Optional[DNSEvent]:
        """Convert a database row to a DNSEvent."""
        query_type_int = row["type"]
        query_type = QUERY_TYPE_MAP.get(query_type_int, f"TYPE{query_type_int}")

        # Skip query types we're not interested in
        if query_type not in self.config.query_types_to_collect:
            return None

        status = row["status"]
        blocked = status in STATUS_BLOCKED_CODES

        timestamp = datetime.fromtimestamp(row["timestamp"], tz=timezone.utc)

        return DNSEvent(
            timestamp=timestamp,
            client=row["client"],
            domain=row["domain"],
            query_type=query_type,
            blocked=blocked,
            response_time_ms=row["reply_time"] / 10.0 if row["reply_time"] else None,
        )

    def _parse_ssh_row(self, parts: list[str]) -> Optional[DNSEvent]:
        """Parse a pipe-delimited row from SSH sqlite3 output."""
        try:
            timestamp_val = float(parts[0])
            client = parts[1]
            domain = parts[2]
            query_type_int = int(parts[3])
            status = int(parts[4])
            reply_time_raw = parts[5] if parts[5] else None

            query_type = QUERY_TYPE_MAP.get(query_type_int, f"TYPE{query_type_int}")

            if query_type not in self.config.query_types_to_collect:
                return None

            blocked = status in STATUS_BLOCKED_CODES
            timestamp = datetime.fromtimestamp(timestamp_val, tz=timezone.utc)

            reply_time_ms = None
            if reply_time_raw:
                reply_time_ms = float(reply_time_raw) / 10.0

            self._last_timestamp = timestamp_val

            return DNSEvent(
                timestamp=timestamp,
                client=client,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                response_time_ms=reply_time_ms,
            )
        except (ValueError, IndexError):
            return None

    @property
    def last_timestamp(self) -> Optional[float]:
        """Return the timestamp of the last collected event."""
        return self._last_timestamp
