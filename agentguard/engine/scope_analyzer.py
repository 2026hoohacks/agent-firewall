"""Scope analyzer for AgentGuard.

Derives a strict scope model from the user's stated goal and determines
whether a proposed action is necessary, narrowly scoped, or overreaching.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from agentguard.models import ScopeAlignment, ScopeReport

# ---------------------------------------------------------------------------
# Goal → expected-action mappings (heuristic)
# ---------------------------------------------------------------------------

_GOAL_ACTION_MAP: Dict[str, Dict[str, List[str]]] = {
    "summarize": {
        "required": ["read"],
        "allowed_tools": ["read_email", "read_file", "read_document", "get_email",
                          "list_emails", "search_email", "read_url", "fetch_url"],
        "disallowed_tools": ["send_email", "delete_file", "execute_command", "upload_file",
                             "run_command", "shell", "transfer_funds"],
    },
    "draft": {
        "required": ["read", "write_draft"],
        "allowed_tools": ["read_email", "read_file", "create_draft", "write_draft"],
        "disallowed_tools": ["send_email", "delete_file", "execute_command", "upload_file"],
    },
    "reply": {
        "required": ["read", "send"],
        "allowed_tools": ["read_email", "send_email", "create_draft", "reply_email"],
        "disallowed_tools": ["delete_file", "execute_command", "upload_file",
                             "transfer_funds"],
    },
    "debug": {
        "required": ["read_file"],
        "allowed_tools": ["read_file", "list_dir", "search_file", "grep",
                          "view_file", "run_command"],
        "disallowed_tools": ["send_email", "upload_file", "transfer_funds",
                             "delete_file", "modify_permissions"],
    },
    "list": {
        "required": ["list"],
        "allowed_tools": ["list_emails", "list_files", "list_events",
                          "list_calendar", "list_dir", "search"],
        "disallowed_tools": ["send_email", "delete_file", "execute_command",
                             "upload_file", "transfer_funds"],
    },
    "check": {
        "required": ["read"],
        "allowed_tools": ["read_email", "read_calendar", "list_events",
                          "get_event", "read_file"],
        "disallowed_tools": ["send_email", "delete_file", "execute_command",
                             "upload_file"],
    },
    "upload": {
        "required": ["read_file", "upload"],
        "allowed_tools": ["read_file", "upload_file", "browser_upload"],
        "disallowed_tools": ["delete_file", "send_email", "transfer_funds"],
    },
    "send": {
        "required": ["send"],
        "allowed_tools": ["send_email", "send_message", "read_email", "create_draft"],
        "disallowed_tools": ["delete_file", "execute_command", "upload_file",
                             "transfer_funds", "modify_permissions"],
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_goal(user_goal: str) -> str | None:
    """Return the best matching goal category, or None."""
    goal_lower = user_goal.lower()
    for keyword in _GOAL_ACTION_MAP:
        if keyword in goal_lower:
            return keyword
    return None


def _tool_is_obviously_unrelated(tool: str, goal_category: str | None) -> bool:
    """Return True if the tool is obviously outside scope for a given goal."""
    if goal_category is None:
        return False
    mapping = _GOAL_ACTION_MAP.get(goal_category, {})
    disallowed = mapping.get("disallowed_tools", [])
    return tool.lower() in [t.lower() for t in disallowed]


def _tool_is_expected(tool: str, goal_category: str | None) -> bool:
    """Return True if the tool is on the expected list for this goal."""
    if goal_category is None:
        return False  # unknown goal, can't confirm
    mapping = _GOAL_ACTION_MAP.get(goal_category, {})
    allowed = mapping.get("allowed_tools", [])
    return tool.lower() in [t.lower() for t in allowed]


# ---------------------------------------------------------------------------
# Overreach detectors
# ---------------------------------------------------------------------------

_BROAD_PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r"^/$"),
    re.compile(r"^~/?$"),
    re.compile(r"^/Users/?$", re.I),
    re.compile(r"^/home/?$", re.I),
    re.compile(r"^[A-Z]:\\?$", re.I),
    re.compile(r"\*\*|\*$"),  # wildcards in path
]


def _path_is_overbroad(path: str) -> bool:
    """Return True if the path is too broad (root, home, wildcard)."""
    for pat in _BROAD_PATH_PATTERNS:
        if pat.search(path.strip()):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    user_goal: str,
    tool: str,
    action: str | None,
    arguments: dict,
) -> ScopeReport:
    """Analyze whether a proposed action aligns with the user's stated goal.

    Returns a ScopeReport with alignment, necessity score, and reasoning.
    """
    reasoning: list[str] = []
    goal_category = _classify_goal(user_goal)
    necessity = 1.0  # start optimistic

    # 1) Classify the goal
    if goal_category:
        reasoning.append(f"User goal classified as: '{goal_category}'")
    else:
        reasoning.append("User goal could not be classified into a known category")
        necessity -= 0.1

    # 2) Check if tool is expected
    if _tool_is_expected(tool, goal_category):
        reasoning.append(f"Tool '{tool}' is expected for goal '{goal_category}'")
    elif _tool_is_obviously_unrelated(tool, goal_category):
        reasoning.append(f"Tool '{tool}' is on the disallowed list for goal '{goal_category}'")
        necessity -= 0.5
    else:
        reasoning.append(f"Tool '{tool}' is not on the expected list but not explicitly disallowed")
        necessity -= 0.2

    # 3) Check for overbroad paths
    from agentguard.engine.sensitive_matcher import extract_paths_from_arguments
    paths = extract_paths_from_arguments(arguments)
    for p in paths:
        if _path_is_overbroad(p):
            reasoning.append(f"Path '{p}' appears overbroad (root/home/wildcard)")
            necessity -= 0.3

    # 4) Determine alignment
    if necessity >= 0.7:
        alignment = ScopeAlignment.WITHIN_SCOPE
    elif necessity >= 0.4:
        alignment = ScopeAlignment.AMBIGUOUS
    else:
        alignment = ScopeAlignment.OUT_OF_SCOPE

    necessity = max(0.0, round(necessity, 2))

    return ScopeReport(
        user_goal=user_goal,
        required_actions=_GOAL_ACTION_MAP.get(goal_category or "", {}).get("required", []),
        alignment=alignment,
        necessity_score=necessity,
        reasoning=reasoning,
    )
