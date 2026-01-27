"""Log collectors for various data sources."""

from agentmon.collectors.pihole import PiholeCollector
from agentmon.collectors.pihole_log import PiholeLogCollector

__all__ = ["PiholeCollector", "PiholeLogCollector"]
