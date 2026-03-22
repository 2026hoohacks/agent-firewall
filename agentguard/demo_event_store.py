"""In-memory demo event store for the dashboard."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict, List, Literal, Optional

from agentguard.interceptor import get_events as get_interceptor_events

_lock = threading.Lock()
_events: deque[Dict[str, Any]] = deque(maxlen=1000)
_next_id = 1


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def list_events() -> List[Dict[str, Any]]:
    with _lock:
        return [dict(e) for e in reversed(_events)]


def get_event(event_id: int) -> Optional[Dict[str, Any]]:
    with _lock:
        for e in _events:
            if e["id"] == event_id:
                return dict(e)
    return None


def apply_decision(event_id: int, decision: Literal["approve", "block"]) -> Optional[Dict[str, Any]]:
    with _lock:
        for e in _events:
            if e["id"] != event_id:
                continue
            if e.get("status") != "pending":
                return dict(e)
            e["status"] = "allowed" if decision == "approve" else "blocked"
            return dict(e)
    return None


def summary() -> Dict[str, Any]:
    events = get_interceptor_events()
    total = len(events)
    blocked = sum(1 for e in events if e.get("status") == "blocked")
    return {
        "session_active": True,
        "total_events": total,
        "blocked_actions": blocked,
    }


def report_payload() -> Dict[str, Any]:
    events = get_interceptor_events()
    s = summary()
    return {
        "generated_at": _iso(time.time()),
        "summary": s,
        "events": events,
    }


def reset_demo() -> None:
    """Test helper: clear store."""
    global _events, _next_id
    with _lock:
        _events.clear()
        _next_id = 1
