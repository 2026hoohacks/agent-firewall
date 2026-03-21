"""Server-rendered pages (Jinja2)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from agentguard.api.auth import effective_user, session_user
from agentguard.config.auth_settings import AuthSettings, get_auth_settings

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(tags=["frontend"])


def _show_app_nav(request: Request, settings: AuthSettings) -> bool:
    return session_user(request) is not None or not settings.is_configured


@router.get("/")
async def index(request: Request):
    settings = get_auth_settings()
    user = effective_user(request, settings)
    logged_in = session_user(request) is not None
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "logged_in": logged_in,
            "auth_configured": settings.is_configured,
            "show_app_nav": _show_app_nav(request, settings),
        },
    )


@router.get("/dashboard")
async def dashboard(request: Request):
    settings = get_auth_settings()
    if settings.is_configured and session_user(request) is None:
        return RedirectResponse(url="/", status_code=302)
    user = effective_user(request, settings)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "logged_in": session_user(request) is not None or not settings.is_configured,
            "auth_configured": settings.is_configured,
            "show_app_nav": _show_app_nav(request, settings),
        },
    )


@router.get("/report")
async def report_page(request: Request):
    settings = get_auth_settings()
    if settings.is_configured and session_user(request) is None:
        return RedirectResponse(url="/", status_code=302)
    user = effective_user(request, settings)
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "user": user,
            "logged_in": session_user(request) is not None or not settings.is_configured,
            "auth_configured": settings.is_configured,
            "show_app_nav": _show_app_nav(request, settings),
        },
    )
