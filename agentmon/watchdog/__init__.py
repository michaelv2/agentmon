"""OODA Watchdog — continuous LLM-based traffic monitoring.

Periodically evaluates DNS traffic snapshots using an LLM in an
Observe-Orient-Decide-Act loop, catching patterns that formulaic
rules miss.
"""

from agentmon.watchdog.ooda import OODAWatchdog

__all__ = ["OODAWatchdog"]
