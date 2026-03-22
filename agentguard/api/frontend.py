"""Server-rendered pages (Jinja2)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(tags=["frontend"])


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"show_app_nav": True})


@router.get("/dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"show_app_nav": True})


@router.get("/report")
async def report_page(request: Request):
    return templates.TemplateResponse(request, "report.html", {"show_app_nav": True})
