"""Tests for the sensitive resource matcher."""

import pytest

from agentguard.engine.sensitive_matcher import (
    check_data_classes,
    check_path,
    check_tool,
    extract_paths_from_arguments,
)
from agentguard.models import PolicyConfig, RiskLevel


@pytest.fixture
def config():
    return PolicyConfig()


# ---------------------------------------------------------------------------
# Path checks
# ---------------------------------------------------------------------------

class TestCheckPath:
    """Test path sensitivity detection."""

    @pytest.mark.parametrize("path", [
        "/Users/john/.ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
        "~/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
    ])
    def test_ssh_keys_are_critical(self, config, path):
        report = check_path(path, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.CRITICAL

    @pytest.mark.parametrize("path", [
        "/app/.env",
        "/project/.env.local",
        "/project/.env.production",
    ])
    def test_env_files_are_high(self, config, path):
        report = check_path(path, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.HIGH

    @pytest.mark.parametrize("path", [
        "~/.aws/credentials",
        "/home/user/.aws/config",
    ])
    def test_aws_credentials_are_critical(self, config, path):
        report = check_path(path, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.CRITICAL

    @pytest.mark.parametrize("path", [
        "/server.pem",
        "/keys/cert.pfx",
        "/certs/private.p12",
    ])
    def test_certificate_files(self, config, path):
        report = check_path(path, config)
        assert report.is_sensitive

    @pytest.mark.parametrize("path", [
        "./src/app.py",
        "/Users/me/project/main.js",
        "/tmp/report.txt",
        "./README.md",
    ])
    def test_normal_files_are_safe(self, config, path):
        report = check_path(path, config)
        assert not report.is_sensitive
        assert report.risk_level == RiskLevel.LOW

    def test_allowed_roots_blocks_outside(self):
        config = PolicyConfig(allowed_roots=["/safe/area"])
        report = check_path("/other/area/file.txt", config)
        assert report.is_sensitive
        assert "outside_allowed_roots" in report.categories

    def test_allowed_roots_allows_inside(self):
        config = PolicyConfig(allowed_roots=["/safe/area"])
        report = check_path("/safe/area/file.txt", config)
        # Still not sensitive because the file itself is not a sensitive pattern
        assert not any("outside_allowed_roots" in c for c in report.categories)


# ---------------------------------------------------------------------------
# Tool checks
# ---------------------------------------------------------------------------

class TestCheckTool:
    """Test tool risk classification."""

    def test_send_email_is_high(self, config):
        report = check_tool("send_email", None, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.HIGH

    def test_execute_command_is_critical(self, config):
        report = check_tool("execute_command", None, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.CRITICAL

    def test_normal_tool_is_safe(self, config):
        report = check_tool("list_dir", None, config)
        assert not report.is_sensitive
        assert report.risk_level == RiskLevel.LOW

    def test_blocked_tool(self):
        config = PolicyConfig(blocked_tools=["evil_tool"])
        report = check_tool("evil_tool", None, config)
        assert report.is_sensitive
        assert report.risk_level == RiskLevel.CRITICAL
        assert "blocked_tool" in report.categories

    def test_safe_tool(self):
        config = PolicyConfig(safe_tools=["my_safe_tool"])
        report = check_tool("my_safe_tool", None, config)
        assert not report.is_sensitive


# ---------------------------------------------------------------------------
# Data class checks
# ---------------------------------------------------------------------------

class TestCheckDataClasses:
    """Test data class detection in text."""

    def test_detects_password(self, config):
        report = check_data_classes("the password is hunter2", config)
        assert report.is_sensitive

    def test_detects_api_key(self, config):
        report = check_data_classes("api_key=sk_live_abc123", config)
        assert report.is_sensitive

    def test_detects_ssn(self, config):
        report = check_data_classes("SSN: 123-45-6789", config)
        assert report.is_sensitive

    def test_clean_text_is_safe(self, config):
        report = check_data_classes("The weather is nice today", config)
        assert not report.is_sensitive


# ---------------------------------------------------------------------------
# Path extraction
# ---------------------------------------------------------------------------

class TestExtractPaths:
    """Test heuristic path extraction from arguments."""

    def test_extracts_path_key(self):
        paths = extract_paths_from_arguments({"path": "/foo/bar.txt"})
        assert "/foo/bar.txt" in paths

    def test_extracts_file_key(self):
        paths = extract_paths_from_arguments({"file": "./report.pdf"})
        assert "./report.pdf" in paths

    def test_extracts_absolute_path_from_unknown_key(self):
        paths = extract_paths_from_arguments({"target_location": "/etc/hosts"})
        assert "/etc/hosts" in paths

    def test_ignores_non_path_values(self):
        paths = extract_paths_from_arguments({"query": "search term"})
        assert len(paths) == 0
