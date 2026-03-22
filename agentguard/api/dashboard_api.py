"""JSON API for the dashboard (demo data + decisions)."""

from __future__ import annotations

from typing import Any, Dict, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agentguard.demo_event_store import apply_decision, list_events, report_payload, summary

router = APIRouter(tags=["dashboard-api"])


class DecisionBody(BaseModel):
    event_id: int = Field(..., ge=1)
    decision: Literal["approve", "block"]


@router.get("/events")
async def api_events() -> Dict[str, Any]:
    events = list_events()
    return {"events": events, "summary": summary()}


@router.get("/report")
async def api_report() -> Dict[str, Any]:
    return report_payload()


@router.post("/decision")
async def api_decision(body: DecisionBody) -> Dict[str, Any]:
    updated = apply_decision(body.event_id, body.decision)
    if updated is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"ok": True, "event": updated, "summary": summary()}
