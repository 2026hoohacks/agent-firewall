"""Pydantic models for AgentGuard request/response structures."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    ASK_USER = "ASK_USER"
    DENY = "DENY"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScopeAlignment(str, Enum):
    WITHIN_SCOPE = "within_scope"
    AMBIGUOUS = "ambiguous"
    OUT_OF_SCOPE = "out_of_scope"


class ExfiltrationRisk(str, Enum):
    NONE = "none"
    POSSIBLE = "possible"
    LIKELY = "likely"


class InstructionSource(str, Enum):
    EXPLICIT_USER_REQUEST = "explicit_user_request"
    DEVELOPER_POLICY = "developer_policy"
    UNTRUSTED_CONTENT = "untrusted_content"
    MODEL_INFERENCE = "model_inference"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ToolRequest(BaseModel):
    """An action the AI agent wants to execute."""

    tool: str = Field(..., description="Name of the tool to invoke")
    action: Optional[str] = Field(None, description="Sub-action within the tool")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    user_goal: str = Field(..., description="The user's stated goal / original request")
    context: Optional[str] = Field(
        None,
        description="Additional context: content that triggered this action, justification, etc.",
    )
    source_content: Optional[str] = Field(
        None,
        description="Raw content the model is reacting to (email body, webpage text, etc.)",
    )


# ---------------------------------------------------------------------------
# Report models (internal analysis)
# ---------------------------------------------------------------------------

class SensitivityReport(BaseModel):
    """Result of deterministic sensitive-resource matching."""

    is_sensitive: bool = False
    matched_patterns: List[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    categories: List[str] = Field(default_factory=list)


class InjectionReport(BaseModel):
    """Result of prompt-injection detection."""

    detected: bool = False
    confidence: float = 0.0
    matched_indicators: List[str] = Field(default_factory=list)


class ScopeReport(BaseModel):
    """Result of scope analysis."""

    user_goal: str = ""
    required_actions: List[str] = Field(default_factory=list)
    alignment: ScopeAlignment = ScopeAlignment.WITHIN_SCOPE
    necessity_score: float = 1.0
    reasoning: List[str] = Field(default_factory=list)


class DataFlowReport(BaseModel):
    """Result of data-flow / exfiltration analysis."""

    source_type: str = ""
    sink_type: str = ""
    exfiltration_risk: ExfiltrationRisk = ExfiltrationRisk.NONE
    reasoning: List[str] = Field(default_factory=list)


class LLMAnalysis(BaseModel):
    """Result of LLM-powered deep analysis."""

    scope_alignment: ScopeAlignment = ScopeAlignment.AMBIGUOUS
    risk_level: RiskLevel = RiskLevel.MEDIUM
    recommended_verdict: VerdictType = VerdictType.ASK_USER
    reasoning: str = ""
    is_suspicious: bool = False
    safe_alternative: Optional[str] = None


# ---------------------------------------------------------------------------
# Audit & Verdict models (output)
# ---------------------------------------------------------------------------

class AuditLog(BaseModel):
    """Structured audit trail for a single evaluation."""

    user_goal: str
    requested_action: str
    resource_targets: List[str] = Field(default_factory=list)
    data_classes: List[str] = Field(default_factory=list)
    source_of_instruction: List[InstructionSource] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    scope_alignment: ScopeAlignment = ScopeAlignment.WITHIN_SCOPE
    sensitivity_match: List[str] = Field(default_factory=list)
    exfiltration_risk: ExfiltrationRisk = ExfiltrationRisk.NONE
    deterministic_checks_used: List[str] = Field(default_factory=list)


class SanitizedAction(BaseModel):
    """The exact action that is allowed / presented for approval / blocked."""

    tool: Optional[str] = None
    action: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    """The full AgentGuard evaluation verdict."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    verdict: VerdictType
    risk_level: RiskLevel
    policy_summary: str
    detailed_reasoning: List[str] = Field(default_factory=list)
    user_message: str
    required_user_confirmation: bool = False
    safe_alternative: Optional[str] = None
    sanitized_action: SanitizedAction = Field(default_factory=SanitizedAction)
    audit_log: AuditLog


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

class PolicyConfig(BaseModel):
    """Configurable policy hooks that can be updated at runtime."""

    allowed_roots: List[str] = Field(default_factory=list)
    blocked_path_patterns: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)
    trusted_recipients: List[str] = Field(default_factory=list)
    sensitive_file_patterns: List[str] = Field(default_factory=list)
    sensitive_data_classes: List[str] = Field(default_factory=list)
    require_approval_for_send: bool = True
    require_approval_for_execute: bool = True
    require_approval_for_delete: bool = True
    require_approval_for_external_upload: bool = True
    safe_tools: List[str] = Field(default_factory=list)
    blocked_tools: List[str] = Field(default_factory=list)
    llm_enabled: bool = False
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str = ""
