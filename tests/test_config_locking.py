"""Tests for config file locking during write operations."""

import threading
from pathlib import Path

import pytest
import tomli

from agentmon.config import append_to_allowlist, update_tunable_field


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Create a temporary config file."""
    path = tmp_path / "agentmon.toml"
    path.write_text('[analyzer]\nallowlist = []\nknown_bad_patterns = []\n')
    return path


class TestConfigFileLocking:
    """Tests for file locking in config write operations."""

    def test_append_to_allowlist_basic(self, config_file: Path) -> None:
        """Basic allowlist append should work."""
        append_to_allowlist("example.com", config_file)
        with open(config_file, "rb") as f:
            data = tomli.load(f)
        assert "example.com" in data["analyzer"]["allowlist"]

    def test_concurrent_writes_no_data_loss(self, config_file: Path) -> None:
        """Concurrent writes should not lose data due to race conditions."""
        errors: list[Exception] = []
        domains = [f"domain-{i}.example.com" for i in range(20)]

        def write_domain(domain: str) -> None:
            try:
                append_to_allowlist(domain, config_file)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_domain, args=(d,)) for d in domains]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"

        with open(config_file, "rb") as f:
            data = tomli.load(f)
        written = set(data["analyzer"]["allowlist"])
        # All domains should be present (no lost writes)
        for domain in domains:
            assert domain in written, f"Lost write: {domain}"

    def test_concurrent_known_bad_pattern_writes(self, config_file: Path) -> None:
        """Concurrent known_bad writes should not lose data."""
        errors: list[Exception] = []
        patterns = [f"pattern-{i}\\.example\\.com" for i in range(20)]

        def write_pattern(pattern: str) -> None:
            try:
                update_tunable_field("add_known_bad", pattern, config_file)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_pattern, args=(p,)) for p in patterns]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"

        with open(config_file, "rb") as f:
            data = tomli.load(f)
        written = set(data["analyzer"]["known_bad_patterns"])
        for pattern in patterns:
            assert pattern in written, f"Lost write: {pattern}"
