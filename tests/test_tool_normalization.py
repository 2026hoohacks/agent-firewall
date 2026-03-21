"""Tests for additive tool-name normalization."""

import pytest

from agentguard.config.config_loader import reset_config
from agentguard.engine.dataflow_analyzer import analyze as analyze_dataflow
from agentguard.engine.policy_engine import evaluate
from agentguard.engine.scope_analyzer import analyze as analyze_scope
from agentguard.engine.sensitive_matcher import check_tool
from agentguard.engine.tool_normalizer import (
    canonicalize_tool_name,
    capability_type_for_tool,
)
from agentguard.models import ExfiltrationRisk, PolicyConfig, ScopeAlignment, ToolRequest, VerdictType


@pytest.fixture(autouse=True)
def _reset_policy_between_tests():
    reset_config()
    yield
    reset_config()


def test_alias_maps_to_canonical_tool_name():
    assert canonicalize_tool_name("fs.read") == "read_file"
    assert canonicalize_tool_name("mail.send") == "send_email"
    assert canonicalize_tool_name("shell.exec") == "run_command"


def test_alias_maps_to_capability_type():
    assert capability_type_for_tool("fs.read") == "filesystem_read"
    assert capability_type_for_tool("mail.send") == "message_send"
    assert capability_type_for_tool("shell.exec") == "command_execution"


def test_check_tool_alias_matches_canonical_behavior():
    config = PolicyConfig()
    canonical = check_tool("send_email", None, config)
    alias = check_tool("mail.send", None, config)
    assert alias.is_sensitive == canonical.is_sensitive
    assert alias.risk_level == canonical.risk_level


def test_scope_analyzer_understands_alias_tool():
    report = analyze_scope("Help me debug this repo", "fs.read", None, {"path": "./src/app.py"})
    assert report.alignment == ScopeAlignment.WITHIN_SCOPE


def test_dataflow_analyzer_understands_alias_tool():
    report = analyze_dataflow("fs.read", None, {"path": "~/.ssh/id_rsa"})
    assert report.exfiltration_risk == ExfiltrationRisk.POSSIBLE


def test_policy_engine_alias_keeps_existing_verdict_behavior():
    canonical = evaluate(
        ToolRequest(
            tool="send_email",
            action=None,
            user_goal="Draft a reply to this client",
            arguments={"to": "client@example.com", "body": "Thank you"},
        )
    )
    alias = evaluate(
        ToolRequest(
            tool="mail.send",
            action=None,
            user_goal="Draft a reply to this client",
            arguments={"to": "client@example.com", "body": "Thank you"},
        )
    )
    assert canonical.verdict == VerdictType.ASK_USER
    assert alias.verdict == canonical.verdict


def test_blocked_tool_alias_is_also_denied():
    from agentguard.config.config_loader import update_config

    update_config({"blocked_tools": ["send_email"]})
    verdict = evaluate(
        ToolRequest(
            tool="mail.send",
            action=None,
            user_goal="Draft a reply to this client",
            arguments={"to": "client@example.com", "body": "Thank you"},
        )
    )
    assert verdict.verdict == VerdictType.DENY


def test_compare_before_after_read_alias_behavior():
    """Before normalization, fs.read would not match debug/read expectations."""
    canonical = evaluate(
        ToolRequest(
            tool="read_file",
            action=None,
            user_goal="Help me debug this repo",
            arguments={"path": "./src/app.py"},
        )
    )
    alias = evaluate(
        ToolRequest(
            tool="fs.read",
            action=None,
            user_goal="Help me debug this repo",
            arguments={"path": "./src/app.py"},
        )
    )

    assert canonical.verdict == VerdictType.ALLOW
    assert alias.verdict == VerdictType.ALLOW


def test_compare_before_after_send_alias_behavior():
    """Before normalization, mail.send would not inherit send_email policy."""
    canonical = evaluate(
        ToolRequest(
            tool="send_email",
            action=None,
            user_goal="Draft a reply to this client",
            arguments={"to": "client@example.com", "body": "Thank you"},
        )
    )
    alias = evaluate(
        ToolRequest(
            tool="mail.send",
            action=None,
            user_goal="Draft a reply to this client",
            arguments={"to": "client@example.com", "body": "Thank you"},
        )
    )

    assert canonical.verdict == VerdictType.ASK_USER
    assert alias.verdict == VerdictType.ASK_USER


def test_compare_before_after_command_alias_behavior():
    """Before normalization, shell.exec would not inherit command approval gating."""
    canonical = evaluate(
        ToolRequest(
            tool="run_command",
            action=None,
            user_goal="Help me debug this repo",
            arguments={"command": "pytest"},
        )
    )
    alias = evaluate(
        ToolRequest(
            tool="shell.exec",
            action=None,
            user_goal="Help me debug this repo",
            arguments={"command": "pytest"},
        )
    )

    assert canonical.verdict == VerdictType.ASK_USER
    assert alias.verdict == VerdictType.ASK_USER


def test_compare_before_after_upload_alias_behavior():
    """Before normalization, file.upload would not inherit upload approval gating."""
    canonical = evaluate(
        ToolRequest(
            tool="upload_file",
            action=None,
            user_goal="Upload the report to our company portal",
            arguments={"file": "./report.pdf", "url": "https://portal.company.com/upload"},
        )
    )
    alias = evaluate(
        ToolRequest(
            tool="file.upload",
            action=None,
            user_goal="Upload the report to our company portal",
            arguments={"file": "./report.pdf", "url": "https://portal.company.com/upload"},
        )
    )

    assert canonical.verdict == VerdictType.ASK_USER
    assert alias.verdict == VerdictType.ASK_USER
