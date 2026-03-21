"""Tests for the scope analyzer."""

import pytest

from agentguard.engine.scope_analyzer import analyze
from agentguard.models import ScopeAlignment


class TestScopeAnalyzer:
    """Test scope analysis for user goal → action alignment."""

    def test_summarize_with_read_email(self):
        report = analyze("Summarize my latest email", "read_email", None, {})
        assert report.alignment == ScopeAlignment.WITHIN_SCOPE
        assert report.necessity_score >= 0.7

    def test_summarize_with_send_email_is_out_of_scope(self):
        report = analyze("Summarize my latest email", "send_email", None, {})
        assert report.alignment in (ScopeAlignment.AMBIGUOUS, ScopeAlignment.OUT_OF_SCOPE)
        assert report.necessity_score < 0.7

    def test_debug_with_read_file(self):
        report = analyze("Help me debug this repo", "read_file", None, {"path": "./src/app.py"})
        assert report.alignment == ScopeAlignment.WITHIN_SCOPE

    def test_debug_with_delete_file_is_bad(self):
        report = analyze("Help me debug this repo", "delete_file", None, {})
        assert report.alignment in (ScopeAlignment.AMBIGUOUS, ScopeAlignment.OUT_OF_SCOPE)

    def test_unknown_goal_does_not_crash(self):
        report = analyze("Do something weird", "some_tool", None, {})
        assert report.alignment is not None

    def test_overbroad_path_reduces_necessity(self):
        report = analyze("Summarize my email", "read_file", None, {"path": "/"})
        # Root path should be flagged
        assert report.necessity_score < 1.0

    def test_upload_with_upload_tool(self):
        report = analyze("Upload the report to our portal", "upload_file", None, {"file": "report.pdf"})
        assert report.alignment == ScopeAlignment.WITHIN_SCOPE

    def test_list_with_list_tool(self):
        report = analyze("List my meetings today", "list_events", None, {})
        assert report.alignment == ScopeAlignment.WITHIN_SCOPE

    def test_check_with_read_calendar(self):
        report = analyze("Check my calendar", "read_calendar", None, {})
        assert report.alignment == ScopeAlignment.WITHIN_SCOPE
