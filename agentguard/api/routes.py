"""API routes for AgentGuard."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from agentguard.config.config_loader import get_config, reset_config, update_config
from agentguard.engine.policy_engine import evaluate, get_audit_entry, get_audit_log, get_stats
from agentguard.interceptor import get_events, read_file as interceptor_read_file, clear_events
from agentguard.models import PolicyConfig, ToolRequest, Verdict

router = APIRouter()

# SSE subscribers
_sse_queues: List[asyncio.Queue] = []


def _broadcast_event(event: Dict[str, Any]) -> None:
    """Push an event to all SSE subscribers."""
    for q in _sse_queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


# ---------------------------------------------------------------------------
# Proxy tool endpoints — ANY agent routes through these
# ---------------------------------------------------------------------------

@router.post("/tools/read_file")
async def proxy_read_file(body: Dict[str, Any]) -> Dict[str, Any]:
    """Proxy for read_file. Any agent calls this instead of reading directly.

    Body: {"path": "..."}
    Returns: {"status": "allowed"|"blocked", "content": "...", "explanation": "..."}
    """
    path = body.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="Missing 'path' in request body")

    result = interceptor_read_file(path)
    status = "allowed" if result["allowed"] else "blocked"

    response = {
        "status": status,
        "path": path,
        "content": result.get("content"),
        "explanation": result["event"].get("explanation", ""),
        "message": result.get("message", ""),
    }

    # Broadcast to SSE subscribers
    _broadcast_event(result["event"])

    return response


# ---------------------------------------------------------------------------
# SSE event stream — real-time UI updates
# ---------------------------------------------------------------------------

@router.get("/events")
async def sse_events(request: Request):
    """Server-Sent Events stream for real-time file access events."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_queues.append(queue)

    async def event_generator():
        try:
            # Send all existing events first
            for evt in get_events():
                yield f"data: {json.dumps(evt)}\n\n"

            # Then stream new events
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        finally:
            _sse_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/events/history")
async def event_history() -> List[Dict[str, Any]]:
    """Return all logged interceptor events."""
    return get_events()


@router.post("/events/clear")
async def clear_event_history() -> Dict[str, str]:
    """Clear the event log."""
    clear_events()
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Evaluate endpoint — the full policy engine
# ---------------------------------------------------------------------------

@router.post("/evaluate", response_model=Verdict)
async def evaluate_action(request: ToolRequest) -> Verdict:
    """Evaluate a proposed tool action and return a verdict."""
    return evaluate(request)


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

@router.get("/policy", response_model=PolicyConfig)
async def get_policy() -> PolicyConfig:
    """Return the current policy configuration."""
    return get_config()


@router.put("/policy", response_model=PolicyConfig)
async def update_policy(updates: Dict[str, Any]) -> PolicyConfig:
    """Update the policy configuration (partial merge)."""
    return update_config(updates)


@router.post("/policy/reset", response_model=PolicyConfig)
async def reset_policy() -> PolicyConfig:
    """Reset the policy configuration to defaults."""
    return reset_config()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/audit", response_model=List[Verdict])
async def list_audit(
    limit: int = Query(50, ge=1, le=500),
    verdict: Optional[str] = Query(None),
    risk: Optional[str] = Query(None),
) -> List[Verdict]:
    """Return audit log entries with optional filters."""
    entries = get_audit_log()
    if verdict:
        entries = [e for e in entries if e.verdict.value == verdict.upper()]
    if risk:
        entries = [e for e in entries if e.risk_level.value == risk.upper()]
    return list(reversed(entries[-limit:]))


@router.get("/audit/{entry_id}", response_model=Verdict)
async def get_audit_by_id(entry_id: str) -> Verdict:
    """Return a single audit entry by ID."""
    entry = get_audit_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return entry


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def stats() -> Dict[str, Any]:
    """Return aggregate statistics."""
    return get_stats()

