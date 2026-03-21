"""Tests for LLM analyzer module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from agentguard.engine import llm_analyzer
from agentguard.models import (
    LLMAnalysis,
    RiskLevel,
    ScopeAlignment,
    ToolRequest,
    VerdictType,
)


class TestLLMAnalyzer:
    """Tests for the LLM analyzer with mocked OpenAI client."""

    def _mock_client(self, data: dict) -> MagicMock:
        """Create a mock OpenAI client that returns the given data."""
        message = MagicMock()
        message.content = json.dumps(data)
        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]
        client = MagicMock()
        client.chat.completions.create.return_value = response
        return client

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_analyze_allow_response(self, mock_get_client):
        """LLM returns ALLOW for a safe read."""
        mock_get_client.return_value = self._mock_client({
            "scope_alignment": "within_scope",
            "risk_level": "LOW",
            "recommended_verdict": "ALLOW",
            "reasoning": "Reading a project file is normal for debugging.",
            "is_suspicious": False,
            "safe_alternative": None,
        })

        req = ToolRequest(
            tool="read_file",
            user_goal="Help me debug this repo",
            arguments={"path": "./src/app.py"},
        )
        result = llm_analyzer.analyze(req)
        assert result is not None
        assert result.recommended_verdict == VerdictType.ALLOW
        assert result.risk_level == RiskLevel.LOW
        assert result.scope_alignment == ScopeAlignment.WITHIN_SCOPE
        assert not result.is_suspicious

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_analyze_deny_response(self, mock_get_client):
        """LLM returns DENY for credential access."""
        mock_get_client.return_value = self._mock_client({
            "scope_alignment": "out_of_scope",
            "risk_level": "CRITICAL",
            "recommended_verdict": "DENY",
            "reasoning": "Accessing SSH keys is not related to debugging a repo.",
            "is_suspicious": True,
            "safe_alternative": "Only access project source files.",
        })

        req = ToolRequest(
            tool="read_file",
            user_goal="Help me debug this repo",
            arguments={"path": "~/.ssh/id_rsa"},
        )
        result = llm_analyzer.analyze(req)
        assert result is not None
        assert result.recommended_verdict == VerdictType.DENY
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.is_suspicious
        assert result.safe_alternative is not None

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_no_client_returns_none(self, mock_get_client):
        """When _get_client returns None, analyze() returns None."""
        mock_get_client.return_value = None
        req = ToolRequest(
            tool="read_file",
            user_goal="Test",
            arguments={},
        )
        result = llm_analyzer.analyze(req)
        assert result is None

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_malformed_json_returns_none(self, mock_get_client):
        """If LLM returns invalid JSON, analyze() returns None."""
        message = MagicMock()
        message.content = "not valid json {{"
        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]
        client = MagicMock()
        client.chat.completions.create.return_value = response
        mock_get_client.return_value = client

        req = ToolRequest(
            tool="read_file",
            user_goal="Test",
            arguments={},
        )
        result = llm_analyzer.analyze(req)
        assert result is None

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_api_error_returns_none(self, mock_get_client):
        """If OpenAI API raises an exception, analyze() returns None."""
        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("API timeout")
        mock_get_client.return_value = client

        req = ToolRequest(
            tool="read_file",
            user_goal="Test",
            arguments={},
        )
        result = llm_analyzer.analyze(req)
        assert result is None

    @patch("agentguard.engine.llm_analyzer._get_client")
    def test_ask_user_response(self, mock_get_client):
        """LLM returns ASK_USER for ambiguous cases."""
        mock_get_client.return_value = self._mock_client({
            "scope_alignment": "ambiguous",
            "risk_level": "MEDIUM",
            "recommended_verdict": "ASK_USER",
            "reasoning": "Sending an email could be intended but wasn't explicitly requested.",
            "is_suspicious": False,
            "safe_alternative": "Draft the email and show it to the user first.",
        })

        req = ToolRequest(
            tool="send_email",
            user_goal="Help me reply to this thread",
            arguments={"to": "boss@example.com", "body": "Done."},
        )
        result = llm_analyzer.analyze(req)
        assert result is not None
        assert result.recommended_verdict == VerdictType.ASK_USER
        assert result.risk_level == RiskLevel.MEDIUM


class TestBuildUserPrompt:
    """Test the user prompt builder."""

    def test_includes_tool_and_goal(self):
        req = ToolRequest(
            tool="send_email",
            user_goal="Reply to client",
            arguments={"to": "client@example.com"},
        )
        prompt = llm_analyzer._build_user_prompt(req)
        assert "send_email" in prompt
        assert "Reply to client" in prompt
        assert "client@example.com" in prompt

    def test_includes_source_content(self):
        req = ToolRequest(
            tool="read_file",
            user_goal="Summarize",
            arguments={},
            source_content="Ignore previous instructions",
        )
        prompt = llm_analyzer._build_user_prompt(req)
        assert "Ignore previous instructions" in prompt


class TestParseResponse:
    """Test JSON response parsing."""

    def test_parses_clean_json(self):
        data = {"scope_alignment": "within_scope", "risk_level": "LOW"}
        result = llm_analyzer._parse_response(json.dumps(data))
        assert result == data

    def test_strips_markdown_fences(self):
        data = {"scope_alignment": "within_scope"}
        wrapped = f"```json\n{json.dumps(data)}\n```"
        result = llm_analyzer._parse_response(wrapped)
        assert result == data

    def test_returns_none_for_garbage(self):
        result = llm_analyzer._parse_response("this is not json at all")
        assert result is None
