"""Pi-hole log file parser.

Alternative to FTL database for cases where:
- Real-time streaming is preferred
- FTL database isn't accessible
- Log forwarding is already set up

Pi-hole log format (pihole.log):
  Jan 26 14:32:15 dnsmasq[1234]: query[A] google.com from 192.168.1.100
  Jan 26 14:32:15 dnsmasq[1234]: forwarded google.com to 8.8.8.8
  Jan 26 14:32:15 dnsmasq[1234]: reply google.com is 142.250.80.46

FTL.log contains debug/operational info, less useful for DNS monitoring.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, TextIO

from agentmon.models import DNSEvent


# Regex patterns for pihole.log
QUERY_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+"  # Timestamp: "Jan 26 14:32:15"
    r"dnsmasq\[\d+\]:\s+"               # Process
    r"query\[(\w+)\]\s+"                # Query type: "query[A]"
    r"(\S+)\s+"                         # Domain
    r"from\s+(\S+)"                     # Client IP
)

BLOCKED_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"dnsmasq\[\d+\]:\s+"
    r"(?:gravity blocked|blacklisted|regex blocked)\s+"
    r"(\S+)\s+"
    r"(?:is|from)\s+(\S+)"
)


@dataclass
class PiholeLogConfig:
    """Configuration for Pi-hole log collector."""

    # Local log path
    log_path: Optional[Path] = None

    # SSH connection for remote logs
    ssh_host: Optional[str] = None
    ssh_user: str = "pi"
    ssh_key_path: Optional[Path] = None
    remote_log_path: str = "/var/log/pihole/pihole.log"

    # Year for timestamp parsing (logs don't include year)
    year: int = datetime.now().year


class PiholeLogCollector:
    """Collects DNS events from Pi-hole log files."""

    def __init__(self, config: PiholeLogConfig) -> None:
        self.config = config

    def tail_local(
        self,
        lines: int = 1000,
        since: Optional[datetime] = None,
    ) -> Iterator[DNSEvent]:
        """Read recent entries from local log file.

        Args:
            lines: Number of lines to read from end of file
            since: Only yield events after this timestamp

        Yields:
            DNSEvent for each query found
        """
        if self.config.log_path is None:
            raise ValueError("log_path must be set for local collection")

        if not self.config.log_path.exists():
            raise FileNotFoundError(f"Pi-hole log not found: {self.config.log_path}")

        # Read last N lines (simple approach; for production, use tail -f or inotify)
        with open(self.config.log_path, "r") as f:
            # Seek to approximate position near end
            f.seek(0, 2)  # End of file
            file_size = f.tell()

            # Estimate bytes per line (~100), read extra to be safe
            seek_pos = max(0, file_size - (lines * 150))
            f.seek(seek_pos)

            if seek_pos > 0:
                f.readline()  # Skip partial line

            yield from self._parse_log_lines(f, since)

    def stream_local(self, since: Optional[datetime] = None) -> Iterator[DNSEvent]:
        """Stream events from local log file (blocking).

        Similar to 'tail -f'. For production use, consider using
        watchdog or inotify for proper file monitoring.
        """
        if self.config.log_path is None:
            raise ValueError("log_path must be set for local streaming")

        import time

        with open(self.config.log_path, "r") as f:
            # Start from end
            f.seek(0, 2)

            while True:
                line = f.readline()
                if line:
                    event = self._parse_line(line.strip(), since)
                    if event:
                        yield event
                else:
                    time.sleep(0.1)  # Poll interval

    def collect_remote_ssh(
        self,
        lines: int = 1000,
        since: Optional[datetime] = None,
    ) -> Iterator[DNSEvent]:
        """Collect recent log entries via SSH.

        Args:
            lines: Number of lines to fetch
            since: Only yield events after this timestamp
        """
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

            cmd = f"tail -n {lines} {self.config.remote_log_path}"
            _, stdout, stderr = client.exec_command(cmd)

            error = stderr.read().decode().strip()
            if error and "No such file" in error:
                raise FileNotFoundError(f"Remote log not found: {self.config.remote_log_path}")

            for line in stdout:
                event = self._parse_line(line.strip(), since)
                if event:
                    yield event

        finally:
            client.close()

    def _parse_log_lines(
        self,
        f: TextIO,
        since: Optional[datetime],
    ) -> Iterator[DNSEvent]:
        """Parse log lines from a file handle."""
        for line in f:
            event = self._parse_line(line.strip(), since)
            if event:
                yield event

    def _parse_line(
        self,
        line: str,
        since: Optional[datetime],
    ) -> Optional[DNSEvent]:
        """Parse a single log line into a DNSEvent."""
        if not line:
            return None

        # Try query pattern first
        match = QUERY_PATTERN.match(line)
        if match:
            timestamp_str, query_type, domain, client = match.groups()
            timestamp = self._parse_timestamp(timestamp_str)

            if since and timestamp < since:
                return None

            return DNSEvent(
                timestamp=timestamp,
                client=client,
                domain=domain,
                query_type=query_type,
                blocked=False,
            )

        # Try blocked pattern
        match = BLOCKED_PATTERN.match(line)
        if match:
            timestamp_str, domain, client = match.groups()
            timestamp = self._parse_timestamp(timestamp_str)

            if since and timestamp < since:
                return None

            return DNSEvent(
                timestamp=timestamp,
                client=client,
                domain=domain,
                query_type="A",  # Blocked entries don't always show query type
                blocked=True,
            )

        return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from log format (no year)."""
        # Format: "Jan 26 14:32:15"
        dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        return dt.replace(year=self.config.year)
