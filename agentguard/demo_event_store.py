"""In-memory demo event store for the dashboard (replace with engine integration later)."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Literal, Optional

_lock = threading.Lock()
_events: List[Dict[str, Any]] = []
_next_id = 1

_SEED: List[Dict[str, Any]] = [
    {
        "type": "prompt_injection",
        "severity": "high",
        "description": "User message contained delimiter escape attempting to override system instructions",
        "status": "pending",
        "policy_reason": "Pattern matched: instruction override / jailbreak",
        "recommended_action": "block",
        "explanation": "The model input nested a fake system block. This is a common prompt-injection tactic.",
    },
    {
        "type": "sensitive_file_access",
        "severity": "high",
        "description": "Agent attempted to read payroll.csv",
        "status": "pending",
        "policy_reason": "Sensitive file category matched: finance/payroll",
        "recommended_action": "block",
        "explanation": "Path matches configured sensitive glob for payroll exports.",
    },
    {
        "type": "large_outbound_transfer",
        "severity": "medium",
        "description": "Tool proposed uploading 48MB archive to external URL",
        "status": "allowed",
        "policy_reason": "Size under emergency cap after user approval",
        "recommended_action": "ask_user",
        "explanation": "Transfer was logged and allowed under demo policy after size check.",
    },
    {
        "type": "suspicious_external_request",
        "severity": "medium",
        "description": "HTTP GET to unknown domain in clipboard paste flow",
        "status": "blocked",
        "policy_reason": "Domain not on allowlist; category: uncategorized",
        "recommended_action": "block",
        "explanation": "Outbound request blocked until domain is reviewed.",
    },
    {
        "type": "unauthorized_tool_call",
        "severity": "critical",
        "description": "Agent invoked shell_exec without explicit grant",
        "status": "blocked",
        "policy_reason": "Tool shell_exec requires elevated consent",
        "recommended_action": "block",
        "explanation": "Shell execution is denied by default in AgentGuard policy.",
    },
    {
        "type": "policy_violation",
        "severity": "low",
        "description": "Attempted to send email without second-factor confirmation",
        "status": "pending",
        "policy_reason": "require_approval_for_send enabled",
        "recommended_action": "ask_user",
        "explanation": "Outbound comms flagged for human confirmation.",
    },
]


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _ensure_seeded() -> None:
    global _next_id
    if _events:
        return
    now = time.time()
    for i, row in enumerate(_SEED):
        _events.append(
            {
                "id": i + 1,
                "timestamp": _iso(now - (len(_SEED) - i) * 120),
                **row,
            }
        )
    _next_id = len(_SEED) + 1


def list_events() -> List[Dict[str, Any]]:
    with _lock:
        _ensure_seeded()
        return [dict(e) for e in reversed(_events)]


def get_event(event_id: int) -> Optional[Dict[str, Any]]:
    with _lock:
        _ensure_seeded()
        for e in _events:
            if e["id"] == event_id:
                return dict(e)
    return None


def apply_decision(event_id: int, decision: Literal["approve", "block"]) -> Optional[Dict[str, Any]]:
    with _lock:
        _ensure_seeded()
        for e in _events:
            if e["id"] != event_id:
                continue
            if e.get("status") != "pending":
                return dict(e)
            e["status"] = "allowed" if decision == "approve" else "blocked"
            return dict(e)
    return None


def summary() -> Dict[str, Any]:
    with _lock:
        _ensure_seeded()
        total = len(_events)
        flagged = sum(1 for e in _events if e["severity"] in ("high", "critical"))
        blocked = sum(1 for e in _events if e["status"] == "blocked")
        pending = sum(1 for e in _events if e["status"] == "pending")
        allowed = sum(1 for e in _events if e["status"] == "allowed")
        # Simple demo risk score 0–100
        risk = min(
            100,
            pending * 12 + blocked * 8 + sum(15 for e in _events if e["severity"] == "critical"),
        )
        return {
            "session_active": True,
            "total_events": total,
            "flagged_events": flagged,
            "blocked_actions": blocked,
            "pending_review": pending,
            "allowed_actions": allowed,
            "risk_score": risk,
        }


def report_payload() -> Dict[str, Any]:
    with _lock:
        _ensure_seeded()
        s = summary()
        return {
            "generated_at": _iso(time.time()),
            "summary": s,
            "events": [dict(e) for e in _events],
        }


def reset_demo() -> None:
    """Test helper: clear store."""
    global _events, _next_id
    with _lock:
        _events = []
        _next_id = 1
