"""Tests for the alert review dashboard."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from agentmon.config import Config
from agentmon.dashboard.app import create_app
from agentmon.models import Alert, DNSEvent, Severity
from agentmon.storage import EventStore


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """Create a test config."""
    cfg = Config()
    cfg.db_path = tmp_path / "test.db"
    return cfg


@pytest.fixture
def populated_db(config: Config) -> None:
    """Populate the test database with sample data."""
    now = datetime.now(timezone.utc)
    with EventStore(config.db_path) as store:
        # Insert DNS events
        for i in range(5):
            store.insert_dns_event(DNSEvent(
                timestamp=now,
                client=f"192.168.1.{10 + i}",
                domain="suspicious.example.com",
                query_type="A",
                blocked=False,
            ))

        # Insert alerts for the domain
        for i in range(3):
            store.insert_alert(Alert(
                id=f"test-alert-{i}",
                timestamp=now,
                severity=Severity.MEDIUM,
                title="New domain detected",
                description=f"First seen domain: suspicious.example.com",
                source_event_type="dns",
                domain="suspicious.example.com",
                client=f"192.168.1.{10 + i}",
                analyzer="dns_baseline",
            ))

        # Insert alerts for another domain
        for i in range(2):
            store.insert_alert(Alert(
                id=f"test-alert-other-{i}",
                timestamp=now,
                severity=Severity.HIGH,
                title="Known-bad pattern",
                description="Matches known-bad pattern",
                source_event_type="dns",
                domain="malware.bad.com",
                client="192.168.1.20",
                analyzer="known_bad",
            ))


@pytest.fixture
def client(config: Config, populated_db: None) -> TestClient:
    """Create a FastAPI test client."""
    app = create_app(config)
    return TestClient(app)


class TestDashboardRoutes:
    """Test dashboard API routes."""

    def test_index_page(self, client: TestClient) -> None:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "agentmon" in resp.text
        assert "Alert Review" in resp.text

    def test_flagged_domains(self, client: TestClient) -> None:
        resp = client.get("/api/flagged-domains")
        assert resp.status_code == 200
        data = resp.json()
        assert "domains" in data
        domains = data["domains"]
        assert len(domains) >= 2

        domain_names = {d["domain"] for d in domains}
        assert "suspicious.example.com" in domain_names
        assert "malware.bad.com" in domain_names

        # Check structure
        suspicious = next(d for d in domains if d["domain"] == "suspicious.example.com")
        assert suspicious["alert_count"] == 3

    def test_domain_clients(self, client: TestClient) -> None:
        resp = client.get("/api/domain/suspicious.example.com/clients")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "suspicious.example.com"
        assert len(data["clients"]) > 0

    def test_acknowledge_domain(self, client: TestClient) -> None:
        resp = client.post("/api/domain/suspicious.example.com/acknowledge")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "suspicious.example.com"
        assert data["acknowledged"] == 3

        # Second call should acknowledge 0
        resp2 = client.post("/api/domain/suspicious.example.com/acknowledge")
        assert resp2.json()["acknowledged"] == 0

    def test_false_positive_domain(self, client: TestClient) -> None:
        resp = client.post("/api/domain/malware.bad.com/false-positive")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "malware.bad.com"
        assert data["marked_false_positive"] == 2

    def test_allowlist_domain(self, client: TestClient, config: Config, tmp_path: Path) -> None:
        # Create a temporary config file
        config_file = tmp_path / "agentmon.toml"
        config_file.write_text('[analyzer]\nallowlist = []\n')

        with patch("agentmon.dashboard.routes.alerts.find_config_file", return_value=config_file):
            resp = client.post("/api/domain/suspicious.example.com/allowlist")
        assert resp.status_code == 200
        data = resp.json()
        assert "suspicious.example.com" in data["message"]
        assert "suspicious.example.com" in config.allowlist

    def test_llm_review_unavailable(self, client: TestClient) -> None:
        resp = client.post("/api/domain/suspicious.example.com/llm-review")
        assert resp.status_code == 503
        assert "not available" in resp.json()["detail"].lower()

    def test_llm_review_with_mock(self, config: Config, populated_db: None) -> None:
        mock_client = MagicMock()
        mock_client.available = True
        mock_client.complete.return_value = "This domain appears to be benign."

        app = create_app(config)
        app.state.anthropic_client = mock_client
        tc = TestClient(app)

        resp = tc.post("/api/domain/suspicious.example.com/llm-review")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "suspicious.example.com"
        assert "benign" in data["analysis"].lower()
        mock_client.complete.assert_called_once()


class TestEventStoreDashboardMethods:
    """Test the new EventStore methods used by the dashboard."""

    def test_get_flagged_domains_summary(self, config: Config, populated_db: None) -> None:
        with EventStore(config.db_path, read_only=True) as store:
            domains = store.get_flagged_domains_summary()
            assert len(domains) >= 2

    def test_get_domain_querying_clients(self, config: Config, populated_db: None) -> None:
        with EventStore(config.db_path, read_only=True) as store:
            clients = store.get_domain_querying_clients("suspicious.example.com")
            assert len(clients) == 5

    def test_acknowledge_domain_alerts(self, config: Config, populated_db: None) -> None:
        with EventStore(config.db_path) as store:
            count = store.acknowledge_domain_alerts("suspicious.example.com")
            assert count == 3

            # Second call returns 0
            count2 = store.acknowledge_domain_alerts("suspicious.example.com")
            assert count2 == 0

    def test_mark_domain_false_positive(self, config: Config, populated_db: None) -> None:
        with EventStore(config.db_path) as store:
            count = store.mark_domain_false_positive("malware.bad.com")
            assert count == 2

    def test_nonexistent_domain(self, config: Config, populated_db: None) -> None:
        with EventStore(config.db_path) as store:
            clients = store.get_domain_querying_clients("doesnt.exist.com")
            assert clients == []
            ack = store.acknowledge_domain_alerts("doesnt.exist.com")
            assert ack == 0
