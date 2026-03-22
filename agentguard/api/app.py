"""FastAPI application factory for AgentGuard."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agentguard.api.dashboard_api import router as dashboard_api_router
from agentguard.api.frontend import router as frontend_router
from agentguard.api.routes import router

_STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "static"
_ROOT = Path(__file__).resolve().parent.parent.parent


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    load_dotenv(_ROOT / ".env", override=False)

    app = FastAPI(
        title="AgentGuard",
        description="AI Agent Safety & Consent-Enforcement Layer",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(dashboard_api_router, prefix="/api")
    app.include_router(router, prefix="/api")
    app.include_router(frontend_router)

    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return app
