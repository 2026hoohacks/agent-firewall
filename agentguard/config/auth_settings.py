"""Auth0 and session-related settings from environment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import quote


@dataclass(frozen=True)
class AuthSettings:
    """Environment-driven Auth0 configuration."""

    auth0_domain: str
    auth0_client_id: str
    auth0_client_secret: str
    auth0_callback_url: str
    auth0_logout_return_to: str
    auth0_audience: str
    secret_key: str

    @property
    def is_configured(self) -> bool:
        return bool(self.auth0_domain and self.auth0_client_id and self.auth0_client_secret)

    @property
    def authorize_base(self) -> str:
        return f"https://{self.auth0_domain.rstrip('/')}/authorize"

    @property
    def token_url(self) -> str:
        return f"https://{self.auth0_domain.rstrip('/')}/oauth/token"

    @property
    def userinfo_url(self) -> str:
        return f"https://{self.auth0_domain.rstrip('/')}/userinfo"

    def logout_redirect_url(self) -> str:
        """Auth0 /v2/logout URL; returnTo must be allowed in Auth0 app settings."""
        base = f"https://{self.auth0_domain.rstrip('/')}/v2/logout"
        client = quote(self.auth0_client_id, safe="")
        ret = quote(self.auth0_logout_return_to, safe="")
        return f"{base}?client_id={client}&returnTo={ret}"


def _strip(s: str) -> str:
    return (s or "").strip()


@lru_cache
def get_auth_settings() -> AuthSettings:
    return AuthSettings(
        auth0_domain=_strip(os.environ.get("AUTH0_DOMAIN", "")),
        auth0_client_id=_strip(os.environ.get("AUTH0_CLIENT_ID", "")),
        auth0_client_secret=_strip(os.environ.get("AUTH0_CLIENT_SECRET", "")),
        auth0_callback_url=_strip(os.environ.get("AUTH0_CALLBACK_URL", "")),
        auth0_logout_return_to=_strip(
            os.environ.get("AUTH0_LOGOUT_URL", "http://localhost:8000/")
        ),
        auth0_audience=_strip(os.environ.get("AUTH0_AUDIENCE", "")),
        secret_key=_strip(os.environ.get("SECRET_KEY", "")) or "dev-insecure-change-me",
    )
