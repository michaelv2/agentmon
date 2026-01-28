"""Slack webhook notifier for alerts."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from agentmon.models import Alert, Severity

logger = logging.getLogger(__name__)

# Slack color codes by severity
SEVERITY_COLORS = {
    Severity.INFO: "#808080",      # gray
    Severity.LOW: "#2196F3",       # blue
    Severity.MEDIUM: "#FF9800",    # orange
    Severity.HIGH: "#F44336",      # red
    Severity.CRITICAL: "#9C27B0",  # purple
}

SEVERITY_EMOJI = {
    Severity.INFO: "i",
    Severity.LOW: "o",
    Severity.MEDIUM: "!",
    Severity.HIGH: "!!",
    Severity.CRITICAL: "!!!",
}


@dataclass
class SlackConfig:
    """Configuration for Slack notifier."""
    webhook_url: str
    min_severity: Severity = Severity.MEDIUM
    enabled: bool = True


class SlackNotifier:
    """Async Slack webhook notifier."""

    def __init__(self, config: SlackConfig) -> None:
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _should_notify(self, alert: Alert) -> bool:
        """Check if alert meets severity threshold."""
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                         Severity.HIGH, Severity.CRITICAL]
        alert_idx = severity_order.index(alert.severity)
        min_idx = severity_order.index(self.config.min_severity)
        return alert_idx >= min_idx

    def _format_message(self, alert: Alert) -> dict:
        """Format alert as Slack message with attachment."""
        emoji = SEVERITY_EMOJI.get(alert.severity, "?")
        color = SEVERITY_COLORS.get(alert.severity, "#808080")

        fields = [
            {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
            {"title": "Analyzer", "value": alert.analyzer, "short": True},
        ]

        if alert.client:
            fields.append({"title": "Client", "value": alert.client, "short": True})
        if alert.domain:
            fields.append({"title": "Domain", "value": f"`{alert.domain}`", "short": True})
        if alert.confidence:
            fields.append({"title": "Confidence", "value": f"{alert.confidence:.0%}", "short": True})

        attachment = {
            "color": color,
            "title": f"[{emoji}] {alert.title}",
            "text": alert.description,
            "fields": fields,
            "footer": "agentmon",
            "ts": int(alert.timestamp.timestamp()),
        }

        if alert.llm_analysis:
            attachment["fields"].append({
                "title": "LLM Analysis",
                "value": alert.llm_analysis[:500],  # Truncate long analysis
                "short": False,
            })

        return {"attachments": [attachment]}

    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to Slack. Returns True if sent successfully."""
        if not self.config.enabled:
            return False

        if not self._should_notify(alert):
            logger.debug(f"Skipping Slack notification: {alert.severity} < {self.config.min_severity}")
            return False

        try:
            client = await self._get_client()
            payload = self._format_message(alert)

            resp = await client.post(self.config.webhook_url, json=payload)

            if resp.status_code == 200:
                logger.debug(f"Slack notification sent for alert: {alert.title}")
                return True
            else:
                logger.warning(f"Slack webhook failed: {resp.status_code} - {resp.text}")
                return False

        except httpx.TimeoutException:
            logger.warning("Slack webhook timeout")
            return False
        except Exception as e:
            logger.warning(f"Slack webhook error: {e}")
            return False
