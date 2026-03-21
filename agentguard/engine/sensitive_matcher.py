"""Deterministic sensitive-resource matcher.

Checks file paths, data classes, and tool names against known sensitive
patterns. Uses hard-coded rules first — no LLM heuristics needed.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, List, Optional, Set

from agentguard.models import PolicyConfig, RiskLevel, SensitivityReport

# ---------------------------------------------------------------------------
# Built-in sensitive path patterns (always active, independent of config)
# ---------------------------------------------------------------------------

_BUILTIN_PATH_PATTERNS: List[str] = [
    # SSH
    "**/.ssh/*", "**/id_rsa*", "**/id_dsa*", "**/id_ed25519*", "**/id_ecdsa*",
    "**/known_hosts", "**/authorized_keys",
    # Env / secrets
    "**/.env", "**/.env.*", "**/.env.local", "**/.env.production",
    "**/.npmrc", "**/.pypirc", "**/.netrc",
    # Git creds
    "**/.git-credentials",
    # Docker / K8s
    "**/.docker/config.json", "**/kubeconfig", "**/.kube/config",
    # Cloud
    "**/.aws/credentials", "**/.aws/config",
    # Terraform
    "**/*.tfstate", "**/*.tfstate.backup",
    # Certs & keys
    "**/*.pem", "**/*.p12", "**/*.pfx", "**/*.key",
]

# Simple regex for path components (case-insensitive)
_SENSITIVE_PATH_KEYWORDS: List[re.Pattern] = [
    re.compile(r"(^|[/\\])\.ssh($|[/\\])", re.I),
    re.compile(r"(^|[/\\])\.env(\.|$)", re.I),
    re.compile(r"(^|[/\\])\.aws[/\\]", re.I),
    re.compile(r"(^|[/\\])\.kube[/\\]", re.I),
    re.compile(r"(^|[/\\])\.docker[/\\]", re.I),
    re.compile(r"id_(rsa|dsa|ed25519|ecdsa)", re.I),
    re.compile(r"private[_-]?key", re.I),
    re.compile(r"credentials?(\.|$|[/\\])", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"password", re.I),
    re.compile(r"token", re.I),
    re.compile(r"(^|[/\\])\.git-credentials$", re.I),
    re.compile(r"(^|[/\\])\.netrc$", re.I),
    re.compile(r"(^|[/\\])\.npmrc$", re.I),
    re.compile(r"(^|[/\\])\.pypirc$", re.I),
    re.compile(r"kubeconfig", re.I),
    re.compile(r"\.tfstate", re.I),
    re.compile(r"\.(pem|p12|pfx)$", re.I),
]

# ---------------------------------------------------------------------------
# Sensitive data-class keywords (found in *content* or arguments)
# ---------------------------------------------------------------------------

_DATA_CLASS_PATTERNS: Dict[str, re.Pattern] = {
    "password": re.compile(r"\bpassword\b", re.I),
    "api_key": re.compile(r"\bapi[_-]?key\b", re.I),
    "access_token": re.compile(r"\baccess[_-]?token\b", re.I),
    "refresh_token": re.compile(r"\brefresh[_-]?token\b", re.I),
    "private_key": re.compile(r"\bprivate[_-]?key\b", re.I),
    "seed_phrase": re.compile(r"\bseed[_-]?phrase\b", re.I),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
}

# ---------------------------------------------------------------------------
# Dangerous tool / action combinations
# ---------------------------------------------------------------------------

_DANGEROUS_TOOLS: Dict[str, RiskLevel] = {
    "send_email": RiskLevel.HIGH,
    "send_message": RiskLevel.HIGH,
    "execute_command": RiskLevel.CRITICAL,
    "run_command": RiskLevel.HIGH,
    "run_shell": RiskLevel.CRITICAL,
    "shell": RiskLevel.CRITICAL,
    "delete_file": RiskLevel.HIGH,
    "remove_file": RiskLevel.HIGH,
    "upload_file": RiskLevel.HIGH,
    "browser_upload": RiskLevel.HIGH,
    "transfer_funds": RiskLevel.CRITICAL,
    "make_purchase": RiskLevel.CRITICAL,
    "modify_permissions": RiskLevel.HIGH,
    "create_webhook": RiskLevel.MEDIUM,
    "install_package": RiskLevel.HIGH,
    "curl": RiskLevel.HIGH,
    "wget": RiskLevel.HIGH,
}



def _glob_match(path: str, pattern: str) -> bool:
    """Match *path* against a glob *pattern* including ** support."""
    normalised = path.replace("\\", "/")
    pat_normalised = pattern.replace("\\", "/")

    # Direct fnmatch (works for simple patterns)
    if fnmatch.fnmatch(normalised, pat_normalised):
        return True

    # For ** patterns, strip the leading **/ and check suffix
    if pat_normalised.startswith("**/"):
        suffix = pat_normalised[3:]  # e.g. ".ssh/*" from "**/.ssh/*"
        # Check if any tail of the path matches the suffix
        parts = normalised.split("/")
        for i in range(len(parts)):
            tail = "/".join(parts[i:])
            if fnmatch.fnmatch(tail, suffix):
                return True

    # For filename-only patterns (no directory separator in pattern)
    # like "*.pem", match against just the filename
    if "/" not in pat_normalised:
        filename = normalised.rsplit("/", 1)[-1] if "/" in normalised else normalised
        if fnmatch.fnmatch(filename, pat_normalised):
            return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_path(path: str, config: PolicyConfig) -> SensitivityReport:
    """Check a file path against sensitive patterns."""
    matched: list[str] = []
    categories: list[str] = []

    # 1) Hard-coded keyword regex
    for regex in _SENSITIVE_PATH_KEYWORDS:
        if regex.search(path):
            matched.append(f"keyword:{regex.pattern}")

    # 2) Built-in glob patterns
    for pat in _BUILTIN_PATH_PATTERNS:
        if _glob_match(path, pat):
            matched.append(f"builtin_glob:{pat}")

    # 3) Config-driven blocked patterns
    for pat in config.blocked_path_patterns:
        if _glob_match(path, pat):
            matched.append(f"policy_glob:{pat}")

    # 4) Config-driven sensitive file patterns
    for pat in config.sensitive_file_patterns:
        if _glob_match(path, pat):
            matched.append(f"sensitive_glob:{pat}")

    # 5) Check allowed_roots (if configured, path must be within one)
    if config.allowed_roots:
        normalised = path.replace("\\", "/")
        inside_root = any(normalised.startswith(r.rstrip("/") + "/") or normalised == r for r in config.allowed_roots)
        if not inside_root:
            matched.append("outside_allowed_roots")
            categories.append("outside_allowed_roots")

    # Determine risk level
    is_sensitive = len(matched) > 0
    if is_sensitive:
        # Private keys and credential files are CRITICAL
        critical_keywords = ["id_rsa", "id_dsa", "id_ed25519", "id_ecdsa",
                             "private_key", ".ssh", "credential", ".aws"]
        if any(kw in path.lower() for kw in critical_keywords):
            risk = RiskLevel.CRITICAL
            categories.append("credentials")
        elif ".env" in path.lower() or "secret" in path.lower():
            risk = RiskLevel.HIGH
            categories.append("secrets")
        else:
            risk = RiskLevel.MEDIUM
            categories.append("sensitive_file")
    else:
        risk = RiskLevel.LOW

    # De-duplicate
    matched = list(dict.fromkeys(matched))
    categories = list(dict.fromkeys(categories))

    return SensitivityReport(
        is_sensitive=is_sensitive,
        matched_patterns=matched,
        risk_level=risk,
        categories=categories,
    )


def check_tool(tool: str, action: Optional[str], config: PolicyConfig) -> SensitivityReport:
    """Check a tool/action name against known dangerous tools."""
    matched: list[str] = []
    categories: list[str] = []

    tool_lower = tool.lower()

    # Blocked tools from policy
    for blocked in config.blocked_tools:
        if tool_lower == blocked.lower():
            return SensitivityReport(
                is_sensitive=True,
                matched_patterns=[f"blocked_tool:{blocked}"],
                risk_level=RiskLevel.CRITICAL,
                categories=["blocked_tool"],
            )

    # Safe tools from policy
    for safe in config.safe_tools:
        if tool_lower == safe.lower():
            return SensitivityReport(is_sensitive=False, risk_level=RiskLevel.LOW)

    # Built-in dangerous tool map
    if tool_lower in _DANGEROUS_TOOLS:
        risk = _DANGEROUS_TOOLS[tool_lower]
        matched.append(f"dangerous_tool:{tool_lower}")
        categories.append("dangerous_tool")
        return SensitivityReport(
            is_sensitive=True,
            matched_patterns=matched,
            risk_level=risk,
            categories=categories,
        )

    return SensitivityReport(is_sensitive=False, risk_level=RiskLevel.LOW)


def check_data_classes(text: str, config: PolicyConfig) -> SensitivityReport:
    """Scan text for sensitive data-class patterns (PII, keys, etc.)."""
    matched: List[str] = []
    categories: List[str] = []

    for name, regex in _DATA_CLASS_PATTERNS.items():
        if regex.search(text):
            matched.append(f"data_class:{name}")
            categories.append(name)

    # Config-driven extra data classes (simple substring match)
    for dc in config.sensitive_data_classes:
        if dc.lower() in text.lower() and f"data_class:{dc}" not in matched:
            matched.append(f"data_class:{dc}")
            categories.append(dc)

    is_sensitive = len(matched) > 0
    risk = RiskLevel.HIGH if is_sensitive else RiskLevel.LOW

    return SensitivityReport(
        is_sensitive=is_sensitive,
        matched_patterns=matched,
        risk_level=risk,
        categories=categories,
    )


def extract_paths_from_arguments(arguments: Dict[str, Any]) -> List[str]:
    """Heuristically extract file paths from a tool's argument dict."""
    paths: List[str] = []
    path_keys = {"path", "file", "filepath", "filename", "file_path",
                 "target", "source", "destination", "src", "dst", "dir",
                 "directory", "folder"}

    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        # Exact key match
        if key.lower() in path_keys:
            paths.append(value)
        # Heuristic: looks like an absolute or relative path
        elif value.startswith("/") or value.startswith("~") or value.startswith("./"):
            paths.append(value)

    return paths
