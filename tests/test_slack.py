"""Tests for Slack notifier."""

import logging
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentmon.models import Alert, Severity
from agentmon.notifiers.slack import SlackConfig, SlackNotifier


def _make_alert(severity: Severity = Severity.HIGH) -> Alert:
    """Create a test alert."""
    return Alert(
        id="test-1",
        timestamp=datetime.now(UTC),
        severity=severity,
        title="Test alert",
        description="Test description",
        source_event_type="dns",
        domain="suspicious.com",
        client="192.168.1.100",
        analyzer="test",
    )


class TestSlackResponseTruncation:
    """Test that error response bodies are truncated before logging."""

    @pytest.mark.asyncio
    async def test_error_response_body_truncated_in_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Slack error response body should be truncated to prevent webhook URL leakage."""
        config = SlackConfig(
            webhook_url="https://hooks.slack.com/services/T00/B00/secret",
        )
        notifier = SlackNotifier(config)

        # Simulate a long error response that contains the webhook URL
        long_body = (
            "Error: invalid payload. "
            "Webhook URL: https://hooks.slack.com/services/T00/B00/secret "
            + "x" * 500
        )

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = long_body

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.is_closed = False
        notifier._client = mock_client

        with caplog.at_level(logging.WARNING):
            result = await notifier.send_alert(_make_alert())

        assert result is False
        # The full response body should NOT be in logs
        for record in caplog.records:
            if "Slack webhook failed" in record.message:
                assert len(record.message) < len(long_body)
                # Should be truncated to 200 chars of body
                break
        else:
            pytest.fail("Expected 'Slack webhook failed' log message")
