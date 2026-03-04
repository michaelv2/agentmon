"""Data models for the OODA Watchdog.

Frozen dataclasses with slots, consistent with the project's style
for potential Rust migration.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SelfAwarenessMetrics:
    """Tracks the watchdog's own operational footprint.

    Included in each LLM prompt so the model is aware of its cumulative
    resource usage — a PoC for self-aware AI monitoring agents.
    """

    total_cycles: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    _latencies: list[float] = field(default_factory=list)
    _start_time: float = field(default_factory=time.monotonic)

    def update_cycle(
        self,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float,
        cost_usd: float,
    ) -> None:
        """Record metrics from a completed OODA cycle."""
        self.total_cycles += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost_usd
        self._latencies.append(latency_ms)

    @property
    def avg_latency_ms(self) -> float:
        """Average API latency across all cycles."""
        if not self._latencies:
            return 0.0
        return sum(self._latencies) / len(self._latencies)

    @property
    def cost_per_hour(self) -> float:
        """Estimated hourly cost based on current rate."""
        elapsed_hours = (time.monotonic() - self._start_time) / 3600
        if elapsed_hours <= 0:
            return 0.0
        return self.total_cost_usd / elapsed_hours

    def to_prompt_section(self) -> str:
        """Format metrics for inclusion in LLM prompt."""
        return (
            f"## Your Operational Footprint\n"
            f"- Cycles completed: {self.total_cycles}\n"
            f"- Total tokens used: {self.total_input_tokens + self.total_output_tokens:,}\n"
            f"- Total cost: ${self.total_cost_usd:.4f}\n"
            f"- Average latency: {self.avg_latency_ms:.0f}ms\n"
            f"- Cost/hour rate: ${self.cost_per_hour:.4f}/h\n"
        )


@dataclass(frozen=True, slots=True)
class OODASnapshot:
    """Observation data collected from DuckDB for one OODA cycle."""

    total_queries: int
    unique_domains: int
    new_domains_count: int
    blocked_count: int
    top_clients: list[dict[str, Any]]
    top_domains: list[dict[str, Any]]
    recent_alerts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON storage and LLM prompt."""
        return {
            "total_queries": self.total_queries,
            "unique_domains": self.unique_domains,
            "new_domains_count": self.new_domains_count,
            "blocked_count": self.blocked_count,
            "top_clients": self.top_clients,
            "top_domains": self.top_domains,
            "recent_alerts": self.recent_alerts,
        }


@dataclass(frozen=True, slots=True)
class OODAConcern:
    """A concern identified by the LLM during Orient+Decide phases."""

    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    recommended_action: str  # "monitor", "alert", "investigate", "tune"
    affected_clients: list[str] = field(default_factory=list)
    affected_domains: list[str] = field(default_factory=list)
    tune_action: str | None = None   # "add_allowlist" | "add_known_bad"
    tune_value: str | None = None    # The domain/pattern to set


@dataclass(slots=True)
class WatchdogReport:
    """Full result of one OODA cycle."""

    cycle_number: int
    snapshot: OODASnapshot
    concerns: list[OODAConcern]
    raw_llm_response: Optional[str] = None
    action_taken: str = "none"
