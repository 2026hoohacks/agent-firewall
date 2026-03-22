"""Data-flow analyzer for AgentGuard.

Classifies sources and sinks, then evaluates whether sensitive data is
moving from a protected source to an external/unintended sink.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from agentguard.models import ExfiltrationRisk, DataFlowReport
from agentguard.engine.tool_normalizer import canonicalize_tool_name

# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

_SENSITIVE_SOURCE_KEYWORDS: List[str] = [
    "ssh", "key", "env", "credential", "secret", "token", "password",
    "private", "wallet", "seed", "certificate", "pem", "pfx", "p12",
    "aws", "kube", "docker", "config.json", "netrc", "npmrc", "pypirc",
    "tfstate", "keychain", "cookie",
]

_LOCAL_SOURCE_TOOLS: Set[str] = {
    "read_file", "view_file", "open_file", "get_file", "cat",
    "read_email", "get_email", "search_email", "list_emails",
    "read_document", "get_document",
    "read_calendar", "list_events", "get_event",
    "query_database", "read_database",
}

_EXTERNAL_SINK_TOOLS: Set[str] = {
    "send_email", "send_message", "reply_email",
    "upload_file", "browser_upload",
    "post_request", "http_post", "curl", "wget",
    "create_webhook", "publish",
    "clipboard_copy",  # risky if secrets are present
    "transfer_funds", "make_purchase",
}


def _classify_source(tool: str, arguments: dict) -> Tuple[str, bool]:
    """Return (source_type, is_sensitive)."""
    tool_lower = canonicalize_tool_name(tool)
    # Check if tool is a local data reader
    if tool_lower in _LOCAL_SOURCE_TOOLS:
        # Check if the path/target looks sensitive
        target = _extract_target(arguments)
        for kw in _SENSITIVE_SOURCE_KEYWORDS:
            if kw in target.lower():
                return ("sensitive_local_file", True)
        return ("local_file", False)
    return ("unknown", False)


def _classify_sink(tool: str, arguments: dict) -> Tuple[str, bool]:
    """Return (sink_type, is_external)."""
    tool_lower = canonicalize_tool_name(tool)
    if tool_lower in _EXTERNAL_SINK_TOOLS:
        return ("external_sink", True)
    if tool_lower in {"write_file", "save_file", "create_file"}:
        return ("local_file_write", False)
    return ("unknown", False)


def _extract_target(arguments: dict) -> str:
    """Best-effort extraction of the primary target from arguments."""
    for key in ("path", "file", "filepath", "file_path", "target",
                "source", "to", "recipient", "url", "endpoint"):
        val = arguments.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    tool: str,
    action: Optional[str],
    arguments: dict,
    prior_actions: Optional[List[Dict]] = None,
) -> DataFlowReport:
    """Analyze data-flow risk for a proposed action.

    Parameters
    ----------
    tool : str
        The tool being invoked.
    action : str | None
        Sub-action.
    arguments : dict
        Tool arguments.
    prior_actions : list[dict] | None
        Previously evaluated actions in this session (for chain analysis).

    Returns
    -------
    DataFlowReport
    """
    reasoning: list[str] = []
    source_type, source_sensitive = _classify_source(tool, arguments)
    sink_type, sink_external = _classify_sink(tool, arguments)

    # Direct exfiltration: this single action reads sensitive + sends external
    # This is unusual (most exfil is a chain), but check anyway
    if source_sensitive and sink_external:
        reasoning.append("Single action both reads sensitive data and writes to external sink")
        return DataFlowReport(
            source_type=source_type,
            sink_type=sink_type,
            exfiltration_risk=ExfiltrationRisk.LIKELY,
            reasoning=reasoning,
        )

    # Chain analysis: did a previous action read sensitive data?
    if prior_actions and sink_external:
        for prior in prior_actions:
            prior_source, prior_sensitive = _classify_source(
                prior.get("tool", ""), prior.get("arguments", {})
            )
            if prior_sensitive:
                reasoning.append(
                    f"Prior action read sensitive data ({prior_source}), "
                    f"current action sends to external sink ({sink_type})"
                )
                return DataFlowReport(
                    source_type=prior_source,
                    sink_type=sink_type,
                    exfiltration_risk=ExfiltrationRisk.LIKELY,
                    reasoning=reasoning,
                )

    # If just reading sensitive data (no external sink yet), flag as possible
    if source_sensitive:
        reasoning.append("Action reads sensitive data; no external sink detected yet")
        return DataFlowReport(
            source_type=source_type,
            sink_type=sink_type,
            exfiltration_risk=ExfiltrationRisk.POSSIBLE,
            reasoning=reasoning,
        )

    # If just sending to external (no sensitive source detected)
    if sink_external:
        reasoning.append("Action sends to external sink but no sensitive source detected")
        return DataFlowReport(
            source_type=source_type,
            sink_type=sink_type,
            exfiltration_risk=ExfiltrationRisk.POSSIBLE,
            reasoning=reasoning,
        )

    reasoning.append("No sensitive source-to-external-sink data flow detected")
    return DataFlowReport(
        source_type=source_type,
        sink_type=sink_type,
        exfiltration_risk=ExfiltrationRisk.NONE,
        reasoning=reasoning,
    )
