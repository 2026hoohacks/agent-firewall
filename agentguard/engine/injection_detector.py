"""Prompt-injection detection for AgentGuard.

Scans source content, context, and justification text for indicators that
the upstream model may have been manipulated by untrusted content.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from agentguard.models import InjectionReport

# ---------------------------------------------------------------------------
# Indicator phrases (case-insensitive substring checks)
# ---------------------------------------------------------------------------

_INJECTION_PHRASES: List[str] = [
    "ignore previous instructions",
    "ignore prior instructions",
    "ignore all instructions",
    "ignore above instructions",
    "disregard previous instructions",
    "disregard prior instructions",
    "forget previous instructions",
    "forget your instructions",
    "override previous instructions",
    "before continuing, read",
    "before you continue, read",
    "verification required",
    "for compliance, attach",
    "for security, attach",
    "send results to",
    "send output to",
    "send the response to",
    "forward this to",
    "developer note",
    "developer override",
    "system override",
    "admin override",
    "do not tell the user",
    "don't tell the user",
    "do not inform the user",
    "do not mention",
    "silently",
    "hidden instruction",
    "secret instruction",
    "you are now",
    "you must now",
    "new instructions",
    "updated instructions",
    "act as if",
    "pretend you are",
    "switch to",
    "enter developer mode",
    "enable developer mode",
    "jailbreak",
    "DAN mode",
    "ignore safety",
    "bypass safety",
    "bypass filters",
    "ignore restrictions",
    "no restrictions",
    "unrestricted mode",
]

# ---------------------------------------------------------------------------
# Structural indicators (regex)
# ---------------------------------------------------------------------------

_STRUCTURAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("html_comment", re.compile(r"<!--.*?-->", re.S)),
    ("markdown_comment", re.compile(r"\[//\]:\s*#")),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("data_uri", re.compile(r"data:[a-z]+/[a-z]+;base64,", re.I)),
    ("zero_width_chars", re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")),
    ("white_on_white", re.compile(r"color:\s*white.*background.*white|color:\s*#fff.*background.*#fff", re.I)),
    ("hidden_text_css", re.compile(r"display:\s*none|visibility:\s*hidden|font-size:\s*0", re.I)),
    ("url_in_instruction", re.compile(r"https?://[^\s]+\.(sh|exe|bat|ps1|py)\b", re.I)),
]

# ---------------------------------------------------------------------------
# Source-authority red flags
# ---------------------------------------------------------------------------

_AUTHORITY_ESCALATION_PHRASES: List[str] = [
    "as the system",
    "i am the developer",
    "with admin privileges",
    "root access",
    "elevated permissions",
    "sudo",
    "run as administrator",
]


def detect(
    source_content: str | None = None,
    context: str | None = None,
    arguments_text: str | None = None,
) -> InjectionReport:
    """Scan provided text for prompt-injection indicators.

    Parameters
    ----------
    source_content:
        Raw untrusted content the model is reacting to (email body, webpage, etc.).
    context:
        Model-provided justification or contextual reasoning.
    arguments_text:
        Serialised tool arguments (for catching paths/URLs smuggled in).

    Returns
    -------
    InjectionReport with detection results.
    """
    matched: list[str] = []

    # Combine all text sources for scanning
    texts = [t for t in (source_content, context, arguments_text) if t]
    combined = "\n".join(texts).lower() if texts else ""

    if not combined:
        return InjectionReport(detected=False, confidence=0.0)

    # 1) Phrase matching
    for phrase in _INJECTION_PHRASES:
        if phrase.lower() in combined:
            matched.append(f"phrase:{phrase}")

    # 2) Structural patterns (run on original case for regex accuracy)
    combined_raw = "\n".join(texts) if texts else ""
    for name, regex in _STRUCTURAL_PATTERNS:
        if regex.search(combined_raw):
            matched.append(f"structural:{name}")

    # 3) Authority escalation
    for phrase in _AUTHORITY_ESCALATION_PHRASES:
        if phrase.lower() in combined:
            matched.append(f"authority:{phrase}")

    # Compute confidence score
    if not matched:
        return InjectionReport(detected=False, confidence=0.0)

    # Each indicator adds to confidence; cap at 1.0
    per_indicator = 0.15
    confidence = min(1.0, len(matched) * per_indicator)

    return InjectionReport(
        detected=True,
        confidence=round(confidence, 2),
        matched_indicators=matched,
    )
