"""Auth0 OAuth (authorization code) and session helpers."""

from __future__ import annotations

import secrets
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from agentguard.config.auth_settings import AuthSettings, get_auth_settings

router = APIRouter(tags=["auth"])


def session_user(request: Request) -> Optional[Dict[str, Any]]:
    return request.session.get("user")


def guest_user() -> Dict[str, Any]:
    return {
        "sub": "guest",
        "email": "guest@demo.local",
        "name": "Guest (configure Auth0)",
        "picture": "",
    }


def effective_user(request: Request, settings: AuthSettings) -> Dict[str, Any]:
    u = session_user(request)
    if u:
        return u
    if not settings.is_configured:
        return guest_user()
    return {}


def require_dashboard_user(request: Request) -> Dict[str, Any]:
    settings = get_auth_settings()
    if not settings.is_configured:
        return guest_user()
    u = session_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return u


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    settings = get_auth_settings()
    if not settings.is_configured:
        return RedirectResponse(url="/?auth=not_configured", status_code=302)

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params: Dict[str, str] = {
        "response_type": "code",
        "client_id": settings.auth0_client_id,
        "redirect_uri": settings.auth0_callback_url,
        "scope": "openid profile email",
        "state": state,
    }
    if settings.auth0_audience:
        params["audience"] = settings.auth0_audience

    url = f"{settings.authorize_base}?{urlencode(params)}"
    return RedirectResponse(url=url, status_code=302)


@router.get("/callback")
async def callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    settings = get_auth_settings()
    if not settings.is_configured:
        return RedirectResponse(url="/?auth=not_configured", status_code=302)

    expected = request.session.pop("oauth_state", None)
    if not expected or state != expected:
        return RedirectResponse(url="/?auth=invalid_state", status_code=302)

    if not code:
        return RedirectResponse(url="/?auth=missing_code", status_code=302)

    body: Dict[str, str] = {
        "grant_type": "authorization_code",
        "client_id": settings.auth0_client_id,
        "client_secret": settings.auth0_client_secret,
        "code": code,
        "redirect_uri": settings.auth0_callback_url,
    }
    if settings.auth0_audience:
        body["audience"] = settings.auth0_audience

    async with httpx.AsyncClient(timeout=30.0) as client:
        tr = await client.post(
            settings.token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if tr.status_code != 200:
            return RedirectResponse(url="/?auth=token_error", status_code=302)
        tokens = tr.json()
        access = tokens.get("access_token")
        if not access:
            return RedirectResponse(url="/?auth=no_token", status_code=302)

        ur = await client.get(
            settings.userinfo_url,
            headers={"Authorization": f"Bearer {access}"},
        )
        if ur.status_code != 200:
            return RedirectResponse(url="/?auth=userinfo_error", status_code=302)
        user = ur.json()

    request.session["user"] = {
        "sub": user.get("sub", ""),
        "email": user.get("email", ""),
        "name": user.get("name") or user.get("nickname") or user.get("email", "User"),
        "picture": user.get("picture", ""),
    }
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    settings = get_auth_settings()
    request.session.clear()
    if settings.is_configured:
        return RedirectResponse(url=settings.logout_redirect_url(), status_code=302)
    return RedirectResponse(url="/", status_code=302)
