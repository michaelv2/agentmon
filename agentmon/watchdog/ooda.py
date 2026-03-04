"""OODA Watchdog — periodic LLM-based traffic evaluation.

Implements an Observe-Orient-Decide-Act loop that periodically:
1. Observes: Queries DuckDB for recent traffic snapshot
2. Orients+Decides: Sends snapshot to Claude for SOC-analyst-style evaluation
3. Acts: Creates alerts for concerns rated "alert" or "investigate"

Designed as a PoC for financial risk management OODA loops, with
self-awareness of its own operational footprint.
"""

import asyncio
import json
import logging
import os
import signal
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agentmon.config import update_tunable_field
from agentmon.llm.anthropic_client import AnthropicClient
from agentmon.models import Alert, Severity
from agentmon.storage import EventStore
from agentmon.watchdog.models import (
    OODAConcern,
    OODASnapshot,
    SelfAwarenessMetrics,
    WatchdogReport,
)
from agentmon.watchdog.queries import (
    get_new_domains_count,
    get_recent_activity_snapshot,
    get_recent_alerts_summary,
    get_top_clients_recent,
    get_top_domains_recent,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a SOC analyst operating in an OODA (Observe-Orient-Decide-Act) loop, \
monitoring DNS traffic for a home/small-office network.

Your job is to evaluate periodic traffic snapshots and identify concerns that \
formulaic rules might miss. You are ONE layer in a defense stack — other analyzers \
handle entropy/DGA detection, known-bad patterns, threat feeds, and device activity \
baselines. Focus on patterns, correlations, and anomalies that require holistic judgment.

You MUST respond with valid JSON in this exact format:
{
  "assessment": "Brief overall assessment of the traffic snapshot",
  "concerns": [
    {
      "title": "Short concern title",
      "description": "Why this is concerning and what it might indicate",
      "severity": "info|low|medium|high|critical",
      "confidence": 0.0-1.0,
      "recommended_action": "monitor|alert|investigate|tune",
      "affected_clients": ["192.168.1.x"],
      "affected_domains": ["example.com"],
      "tune_action": "add_allowlist|add_known_bad (only when recommended_action is tune)",
      "tune_value": "domain or pattern to add (only when recommended_action is tune)"
    }
  ],
  "operational_note": "Optional note about your own resource usage or suggestions"
}

Guidelines:
- Empty concerns array is perfectly fine — most snapshots will be normal
- Only flag "alert" or "investigate" for genuinely suspicious patterns
- Use "monitor" for things worth noting but not yet actionable
- Use "tune" with tune_action/tune_value to suggest config changes (e.g., add a benign \
domain to the allowlist or a malicious pattern to known_bad_patterns)
- Consider time of day, query volumes, domain diversity, and client behavior
- Be specific about what pattern triggered the concern
- You are aware of your own operational cost (shown below) — be efficient
"""


class OODAWatchdog:
    """Periodic LLM-based traffic watchdog using OODA loop."""

    def __init__(
        self,
        store: EventStore,
        llm: AnthropicClient,
        interval_minutes: int = 15,
        max_tokens_per_cycle: int = 1024,
        window_minutes: Optional[int] = None,
        config_path: Optional[Path] = None,
    ) -> None:
        """Initialize the watchdog.

        Args:
            store: EventStore for DuckDB access.
            llm: AnthropicClient for Claude API calls.
            interval_minutes: Minutes between OODA cycles.
            max_tokens_per_cycle: Max output tokens per LLM call.
            window_minutes: Traffic window to observe (default: 2x interval).
            config_path: Path to TOML config file for tune actions.
        """
        self.store = store
        self.llm = llm
        self.interval_minutes = interval_minutes
        self.max_tokens_per_cycle = max_tokens_per_cycle
        self.window_minutes = window_minutes or (interval_minutes * 2)
        self.config_path = config_path

        self._cycle_number = 0
        self._metrics = SelfAwarenessMetrics()
        self._running = False

    def run_cycle(self) -> WatchdogReport:
        """Execute one complete OODA cycle.

        Returns:
            WatchdogReport with snapshot, concerns, and action taken.
        """
        self._cycle_number += 1
        cycle = self._cycle_number

        # === OBSERVE ===
        snapshot = self._observe()

        # Short-circuit: skip LLM if no traffic
        if snapshot.total_queries == 0:
            logger.debug(f"Watchdog cycle {cycle}: no traffic, skipping LLM")
            report = WatchdogReport(
                cycle_number=cycle,
                snapshot=snapshot,
                concerns=[],
                action_taken="skipped_no_traffic",
            )
            self._store_observation(report)
            return report

        # === ORIENT + DECIDE ===
        concerns, raw_response, latency_ms = self._orient_and_decide(snapshot)

        # === ACT ===
        action = self._act(concerns)

        report = WatchdogReport(
            cycle_number=cycle,
            snapshot=snapshot,
            concerns=concerns,
            raw_llm_response=raw_response,
            action_taken=action,
        )

        # Store audit record
        self._store_observation(report, latency_ms=latency_ms)

        return report

    def _observe(self) -> OODASnapshot:
        """Observe phase: query DuckDB for traffic snapshot."""
        conn = self.store.conn
        window = self.window_minutes

        activity = get_recent_activity_snapshot(conn, window)
        top_clients = get_top_clients_recent(conn, window)
        top_domains = get_top_domains_recent(conn, window)
        recent_alerts = get_recent_alerts_summary(conn, window)
        new_domains = get_new_domains_count(conn, window)

        return OODASnapshot(
            total_queries=activity["total_queries"],
            unique_domains=activity["unique_domains"],
            new_domains_count=new_domains,
            blocked_count=activity["blocked_count"],
            top_clients=top_clients,
            top_domains=top_domains,
            recent_alerts=recent_alerts,
        )

    def _orient_and_decide(
        self, snapshot: OODASnapshot
    ) -> tuple[list[OODAConcern], Optional[str], float]:
        """Orient+Decide phases: build prompt and query LLM.

        Returns:
            Tuple of (concerns, raw_response, latency_ms).
        """
        # Build user message with snapshot data and self-awareness
        user_message = self._build_user_message(snapshot)

        start = time.monotonic()
        result = self.llm.complete_with_usage(SYSTEM_PROMPT, user_message)
        latency_ms = (time.monotonic() - start) * 1000

        if result is None:
            logger.warning(f"Watchdog cycle {self._cycle_number}: LLM returned None")
            return [], None, latency_ms

        raw_response = result.text
        input_tokens = result.input_tokens
        output_tokens = result.output_tokens

        # Compute cost from real token counts (Claude Sonnet pricing: ~$3/$15 per M tokens)
        cost = (input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000

        self._metrics.update_cycle(input_tokens, output_tokens, latency_ms, cost)

        # Stash per-cycle token data for _store_observation()
        self._last_input_tokens = input_tokens
        self._last_output_tokens = output_tokens
        self._last_cost = cost

        # Parse concerns from JSON response
        concerns = self._parse_concerns(raw_response)

        return concerns, raw_response, latency_ms

    def _build_user_message(self, snapshot: OODASnapshot) -> str:
        """Build the user message for the LLM with snapshot and metrics."""
        now = datetime.now(timezone.utc)
        data = snapshot.to_dict()

        # Serialize datetimes in alerts for JSON
        for alert in data.get("recent_alerts", []):
            for key, val in alert.items():
                if isinstance(val, datetime):
                    alert[key] = val.isoformat()

        parts = [
            f"## OODA Cycle #{self._cycle_number}",
            f"**Timestamp:** {now.isoformat()}",
            f"**Window:** last {self.window_minutes} minutes",
            "",
            "## Traffic Snapshot",
            f"```json\n{json.dumps(data, indent=2, default=str)}\n```",
            "",
            self._metrics.to_prompt_section(),
        ]

        return "\n".join(parts)

    _VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
    _VALID_TUNE_ACTIONS = frozenset({"add_allowlist", "add_known_bad"})

    def _parse_concerns(self, raw_response: str) -> list[OODAConcern]:
        """Parse LLM JSON response into OODAConcern objects."""
        try:
            # Handle potential markdown code fences
            text = raw_response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                # Remove first and last lines (code fences)
                text = "\n".join(lines[1:-1])

            parsed = json.loads(text)
            concerns = []

            for item in parsed.get("concerns", []):
                severity = item.get("severity", "info")
                if severity not in self._VALID_SEVERITIES:
                    logger.warning(
                        "Watchdog LLM returned unrecognized severity %r, "
                        "defaulting to 'medium'",
                        severity,
                    )
                    severity = "medium"

                concern = OODAConcern(
                    title=item.get("title", "Unknown"),
                    description=item.get("description", ""),
                    severity=severity,
                    confidence=float(item.get("confidence", 0.5)),
                    recommended_action=item.get("recommended_action", "monitor"),
                    affected_clients=item.get("affected_clients", []),
                    affected_domains=item.get("affected_domains", []),
                    tune_action=item.get("tune_action"),
                    tune_value=item.get("tune_value"),
                )
                concerns.append(concern)

            return concerns

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse watchdog LLM response: {e}")
            return []

    def _act(self, concerns: list[OODAConcern]) -> str:
        """Act phase: create alerts for actionable concerns and apply tune actions.

        Returns:
            Summary of actions taken.
        """
        severity_map = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        actions = []
        for concern in concerns:
            if concern.recommended_action in ("alert", "investigate"):
                severity = severity_map.get(concern.severity, Severity.MEDIUM)
                alert = Alert(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    severity=severity,
                    title=f"[Watchdog] {concern.title}",
                    description=concern.description,
                    source_event_type="dns",
                    client=concern.affected_clients[0] if concern.affected_clients else None,
                    domain=concern.affected_domains[0] if concern.affected_domains else None,
                    analyzer="watchdog",
                    confidence=concern.confidence,
                    tags=[concern.recommended_action],
                )
                self.store.insert_alert(alert)
                actions.append(f"{concern.recommended_action}:{concern.title}")
                logger.info(
                    f"Watchdog alert: [{concern.severity}] {concern.title} "
                    f"(action={concern.recommended_action})"
                )
            elif concern.recommended_action == "tune":
                tune_result = self._apply_tune(concern)
                if tune_result:
                    actions.append(tune_result)
            else:
                logger.debug(f"Watchdog monitor: {concern.title}")

        if not actions:
            return "no_action"
        return "; ".join(actions)

    def _apply_tune(self, concern: OODAConcern) -> str | None:
        """Apply a tune action from a concern.

        Returns:
            Action description string, or None if skipped.
        """
        if not concern.tune_action or not concern.tune_value:
            logger.warning(
                "Watchdog tune action missing tune_action or tune_value: %s",
                concern.title,
            )
            return None

        if concern.tune_action not in self._VALID_TUNE_ACTIONS:
            logger.warning(
                "Watchdog LLM returned unrecognized tune_action %r, skipping",
                concern.tune_action,
            )
            return None

        try:
            update_tunable_field(
                concern.tune_action,
                concern.tune_value,
                config_path=self.config_path,
            )
        except (RuntimeError, ValueError, OSError) as e:
            logger.warning("Watchdog tune action failed: %s", e)
            return None

        logger.info(
            "Watchdog tuned config: %s = %r",
            concern.tune_action,
            concern.tune_value,
        )

        # Send SIGHUP to self to trigger config reload
        try:
            os.kill(os.getpid(), signal.SIGHUP)
        except OSError as e:
            logger.warning("Failed to send SIGHUP for config reload: %s", e)

        return f"tune:{concern.tune_action}={concern.tune_value}"

    def _store_observation(
        self,
        report: WatchdogReport,
        latency_ms: float = 0.0,
    ) -> None:
        """Store an observation record for audit trail."""
        # Retrieve per-cycle token data (set by _orient_and_decide, if it ran)
        input_tokens = getattr(self, "_last_input_tokens", None)
        output_tokens = getattr(self, "_last_output_tokens", None)
        estimated_cost = getattr(self, "_last_cost", None)

        try:
            self.store.insert_watchdog_observation(
                observation_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                cycle_number=report.cycle_number,
                snapshot_json=json.dumps(report.snapshot.to_dict(), default=str),
                concerns_json=json.dumps(
                    [
                        {
                            "title": c.title,
                            "severity": c.severity,
                            "action": c.recommended_action,
                            "tune_action": c.tune_action,
                            "tune_value": c.tune_value,
                        }
                        for c in report.concerns
                    ]
                ),
                action_taken=report.action_taken,
                api_latency_ms=latency_ms if latency_ms > 0 else None,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                estimated_cost_usd=estimated_cost,
                model_used=self.llm.config.model if self.llm else None,
            )
        except Exception as e:
            logger.warning(f"Failed to store watchdog observation: {e}")
        finally:
            # Clear per-cycle stash
            self._last_input_tokens = None  # type: ignore[assignment]
            self._last_output_tokens = None  # type: ignore[assignment]
            self._last_cost = None  # type: ignore[assignment]

    async def run_periodic(self) -> None:
        """Run OODA cycles periodically until stopped.

        Runs an initial cycle after a short delay, then repeats at
        the configured interval.
        """
        self._running = True
        interval_seconds = self.interval_minutes * 60

        # Initial delay: shorter of interval or 60s
        initial_delay = min(interval_seconds, 60)
        logger.info(
            f"Watchdog starting: interval={self.interval_minutes}m, "
            f"window={self.window_minutes}m, initial_delay={initial_delay}s"
        )
        await asyncio.sleep(initial_delay)

        while self._running:
            try:
                report = self.run_cycle()
                concern_count = len(report.concerns)
                action_count = sum(
                    1 for c in report.concerns
                    if c.recommended_action in ("alert", "investigate")
                )
                logger.info(
                    f"Watchdog cycle {report.cycle_number}: "
                    f"{report.snapshot.total_queries} queries, "
                    f"{concern_count} concerns, {action_count} actions, "
                    f"cost=${self._metrics.total_cost_usd:.4f}"
                )
            except Exception:
                logger.exception(f"Watchdog cycle {self._cycle_number} failed")

            await asyncio.sleep(interval_seconds)

    def stop(self) -> None:
        """Signal the periodic loop to stop."""
        self._running = False
