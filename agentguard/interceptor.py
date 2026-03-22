"""AgentGuard Interceptor — the core product.

Wraps file operations with a safety check. Every file access goes
through here. Sensitive paths are blocked before the filesystem
is ever touched. String matching — cannot be tricked by prompts.
"""

from __future__ import annotations

import os
import asyncio
import json
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Sensitive path patterns — hard rules, no AI, no ambiguity
# ---------------------------------------------------------------------------

SENSITIVE = [
    ".ssh", ".env", "id_rsa", "id_dsa", "id_ed25519", "id_ecdsa",
    "credentials", ".pem", ".pfx", ".p12", ".key",
    "authorized_keys", "known_hosts",
    ".aws", ".kube", ".docker",
    "token", "secret", "password",
    ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    "kubeconfig", ".tfstate",
]

# Plain-English explanations for sensitive file types
_EXPLANATIONS: Dict[str, str] = {
    ".ssh": "This folder contains your SSH keys — used to log into servers and GitHub.",
    "id_rsa": "This is your private SSH key. Exposing it could compromise all your servers.",
    "id_ed25519": "This is your private SSH key. Exposing it could compromise all your servers.",
    ".env": "This file contains environment variables — often API keys and database passwords.",
    "credentials": "This file contains login credentials for cloud services.",
    ".aws": "This folder contains your AWS credentials — full access to your cloud account.",
    ".pem": "This is a certificate/key file used for secure connections.",
    "token": "This file may contain authentication tokens.",
    "secret": "This file may contain secret keys or passwords.",
    "password": "This file may contain passwords.",
    ".kube": "This contains Kubernetes cluster credentials.",
}

# In-memory event log — the UI reads from this
_event_log: deque[Dict[str, Any]] = deque(maxlen=1000)
_pending_blocks: Dict[str, asyncio.Future] = {}


def get_events() -> List[Dict[str, Any]]:
    """Return all logged events."""
    return list(_event_log)


def clear_events() -> None:
    """Clear the event log."""
    _event_log.clear()


def _explain(path: str) -> str:
    """Generate a plain-English explanation for why a path is sensitive."""
    path_lower = path.lower()
    for keyword, explanation in _EXPLANATIONS.items():
        if keyword in path_lower:
            return explanation
    return "This file may contain sensitive data that should not be exposed."


def _is_sensitive(path: str) -> bool:
    """Check if a path contains sensitive patterns. String matching only."""
    path_lower = path.lower()
    return any(s in path_lower for s in SENSITIVE)


def _log_event(path: str, action: str, status: str, detail: str = "") -> Dict[str, Any]:
    """Log a file access event."""
    event = {
        "id": f"evt-{len(_event_log) + 1}",
        "timestamp": time.time(),
        "path": path,
        "action": action,
        "status": status,  # "allowed", "blocked", "pending"
        "detail": detail,
        "explanation": _explain(path) if status != "allowed" else "",
    }
    _event_log.append(event)
    return event


# ---------------------------------------------------------------------------
# The interceptor — THIS IS THE WHOLE PRODUCT
# ---------------------------------------------------------------------------

def read_file(path: str, base_dir: str = "demo_files") -> Dict[str, Any]:
    """Intercepted read_file. Checks path, blocks or allows.

    Returns a dict with:
      - allowed: bool
      - content: str or None
      - event: the logged event
    """
    # Resolve the actual file path
    if not os.path.isabs(path):
        full_path = os.path.join(base_dir, path)
    else:
        full_path = path

    # THE CHECK — string matching, no AI, no ambiguity
    if _is_sensitive(path):
        event = _log_event(path, "read_file", "blocked",
                           _explain(path))
        return {
            "allowed": False,
            "content": None,
            "event": event,
            "message": f"⛔ BLOCKED: Access to '{path}' was denied. {_explain(path)}",
        }

    # Safe — read the file
    try:
        with open(full_path, "r") as f:
            content = f.read()
        event = _log_event(path, "read_file", "allowed")
        return {
            "allowed": True,
            "content": content,
            "event": event,
            "message": f"✅ Read '{path}' successfully.",
        }
    except FileNotFoundError:
        event = _log_event(path, "read_file", "allowed", "file not found")
        return {
            "allowed": True,
            "content": None,
            "event": event,
            "message": f"File '{path}' not found.",
        }
