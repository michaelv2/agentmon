"""Syslog receiver for push-based log collection.

Receives syslog messages from edge devices (Pi-hole, OpenWRT) over UDP/TCP.
This replaces SSH-based pull collection, improving security by ensuring
the hub holds no credentials to network infrastructure.

Supports:
- RFC 3164 (BSD syslog) format
- RFC 5424 (modern syslog) format
- UDP and TCP protocols
- Optional IP allowlist for security
"""

import asyncio
import logging
import re
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


# RFC 3164 priority and timestamp pattern
# <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
RFC3164_PATTERN = re.compile(
    r"^<(\d{1,3})>"  # Priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp: "Jan 26 14:32:15"
    r"(\S+)\s+"  # Hostname
    r"(\S+?)(?:\[\d+\])?:\s*"  # Tag (program name), optional PID
    r"(.*)$"  # Message
)

# RFC 5424 pattern
# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"^<(\d{1,3})>(\d)\s+"  # Priority and version
    r"(\S+)\s+"  # Timestamp (ISO 8601)
    r"(\S+)\s+"  # Hostname
    r"(\S+)\s+"  # App-name
    r"(\S+)\s+"  # Procid
    r"(\S+)\s+"  # Msgid
    r"(?:\[.*?\]|-)\s*"  # Structured-data (skip for now)
    r"(.*)$"  # Message
)


@dataclass
class SyslogMessage:
    """Parsed syslog message."""

    timestamp: datetime
    hostname: str
    tag: str  # Program/application name (e.g., "dnsmasq", "dropbear")
    message: str
    facility: int = 0
    severity: int = 0
    source_ip: str | None = None

    @property
    def facility_name(self) -> str:
        """Human-readable facility name."""
        facilities = [
            "kern", "user", "mail", "daemon", "auth", "syslog",
            "lpr", "news", "uucp", "cron", "authpriv", "ftp",
            "ntp", "audit", "alert", "clock",
            "local0", "local1", "local2", "local3",
            "local4", "local5", "local6", "local7",
        ]
        if self.facility < len(facilities):
            return facilities[self.facility]
        return f"facility{self.facility}"

    @property
    def severity_name(self) -> str:
        """Human-readable severity name."""
        severities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        if self.severity < len(severities):
            return severities[self.severity]
        return f"severity{self.severity}"


@dataclass
class SyslogConfig:
    """Configuration for syslog receiver."""

    port: int = 1514
    protocol: str = "udp"  # "udp", "tcp", or "both"
    bind_address: str = "0.0.0.0"
    allowed_ips: list[str] = field(default_factory=list)  # Empty = allow all
    year: int = field(default_factory=lambda: datetime.now().year)
    buffer_size: int = 65535  # Max UDP packet size


def parse_syslog_message(
    data: bytes,
    source_ip: str,
    year: int = datetime.now().year,
) -> SyslogMessage | None:
    """Parse a raw syslog message.

    Args:
        data: Raw syslog message bytes
        source_ip: IP address of the sender
        year: Year to use for timestamps (syslog often omits year)

    Returns:
        Parsed SyslogMessage or None if parsing fails
    """
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    if not text:
        return None

    # Try RFC 5424 first (has version number after priority)
    match = RFC5424_PATTERN.match(text)
    if match:
        pri, _version, timestamp_str, hostname, app_name, _procid, _msgid, message = match.groups()
        priority = int(pri)
        facility = priority >> 3
        severity = priority & 0x07

        # Parse ISO 8601 timestamp
        try:
            # Handle common formats
            timestamp_str = timestamp_str.replace("Z", "+00:00")
            if "T" in timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str)
            else:
                timestamp = datetime.now()
        except ValueError:
            timestamp = datetime.now()

        return SyslogMessage(
            timestamp=timestamp,
            hostname=hostname,
            tag=app_name,
            message=message,
            facility=facility,
            severity=severity,
            source_ip=source_ip,
        )

    # Try RFC 3164
    match = RFC3164_PATTERN.match(text)
    if match:
        pri, timestamp_str, hostname, tag, message = match.groups()
        priority = int(pri)
        facility = priority >> 3
        severity = priority & 0x07

        # Parse BSD timestamp (no year)
        try:
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            timestamp = dt.replace(year=year)
        except ValueError:
            timestamp = datetime.now()

        return SyslogMessage(
            timestamp=timestamp,
            hostname=hostname,
            tag=tag,
            message=message,
            facility=facility,
            severity=severity,
            source_ip=source_ip,
        )

    # Fallback: treat entire message as content
    return SyslogMessage(
        timestamp=datetime.now(),
        hostname=source_ip,
        tag="unknown",
        message=text,
        source_ip=source_ip,
    )


# Type alias for message handler callback
MessageHandler = Callable[[SyslogMessage], None]


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(
        self,
        handler: MessageHandler,
        config: SyslogConfig,
    ) -> None:
        self.handler = handler
        self.config = config
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]

        # Check IP allowlist
        if self.config.allowed_ips and source_ip not in self.config.allowed_ips:
            logger.debug(f"Rejected syslog from {source_ip} (not in allowlist)")
            return

        msg = parse_syslog_message(data, source_ip, self.config.year)
        if msg:
            try:
                self.handler(msg)
            except Exception as e:
                logger.error(f"Error handling syslog message: {e}")


class TCPSyslogProtocol(asyncio.Protocol):
    """TCP protocol handler for syslog messages."""

    def __init__(
        self,
        handler: MessageHandler,
        config: SyslogConfig,
    ) -> None:
        self.handler = handler
        self.config = config
        self.transport: asyncio.Transport | None = None
        self.buffer = b""
        self.peer: tuple[str, int] | None = None

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.peer = transport.get_extra_info("peername")

        if self.peer:
            source_ip = self.peer[0]
            if self.config.allowed_ips and source_ip not in self.config.allowed_ips:
                logger.debug(f"Rejected TCP connection from {source_ip} (not in allowlist)")
                transport.close()
                return

        logger.debug(f"TCP connection from {self.peer}")

    def data_received(self, data: bytes) -> None:
        self.buffer += data

        # Process complete messages (newline-delimited for TCP syslog)
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if line:
                source_ip = self.peer[0] if self.peer else "unknown"
                msg = parse_syslog_message(line, source_ip, self.config.year)
                if msg:
                    try:
                        self.handler(msg)
                    except Exception as e:
                        logger.error(f"Error handling syslog message: {e}")

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug(f"TCP connection closed from {self.peer}")


class SyslogReceiver:
    """Async syslog receiver supporting UDP and TCP."""

    def __init__(
        self,
        config: SyslogConfig,
        handler: MessageHandler,
    ) -> None:
        """Initialize the syslog receiver.

        Args:
            config: Receiver configuration
            handler: Callback function for each received message
        """
        self.config = config
        self.handler = handler
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        """Start the syslog receiver."""
        loop = asyncio.get_running_loop()
        self._running = True

        if self.config.protocol in ("udp", "both"):
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: UDPSyslogProtocol(self.handler, self.config),
                local_addr=(self.config.bind_address, self.config.port),
            )
            self._udp_transport = transport
            logger.info(f"Syslog UDP listening on {self.config.bind_address}:{self.config.port}")

        if self.config.protocol in ("tcp", "both"):
            self._tcp_server = await loop.create_server(
                lambda: TCPSyslogProtocol(self.handler, self.config),
                self.config.bind_address,
                self.config.port,
            )
            logger.info(f"Syslog TCP listening on {self.config.bind_address}:{self.config.port}")

    async def stop(self) -> None:
        """Stop the syslog receiver."""
        self._running = False

        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
            logger.info("Syslog UDP stopped")

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
            logger.info("Syslog TCP stopped")

    @property
    def is_running(self) -> bool:
        """Check if the receiver is running."""
        return self._running

    async def run_forever(self) -> None:
        """Run the receiver until interrupted."""
        await self.start()

        # Set up signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            logger.info("Shutdown signal received")
            stop_event.set()

        # Register signal handlers
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                # Signal handlers not supported on this platform (e.g., Windows)
                pass

        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            # Remove signal handlers before stopping
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.remove_signal_handler(sig)
                except (NotImplementedError, ValueError):
                    pass
            await self.stop()
