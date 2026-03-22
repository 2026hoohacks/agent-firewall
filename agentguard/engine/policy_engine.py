"""AgentGuard Policy Engine — the central decision-maker.

Orchestrates all sub-analyzers and produces a final Verdict.
Follows the 10-step reasoning procedure from the specification.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from agentguard.config.config_loader import get_config
from agentguard.engine import (
    dataflow_analyzer,
    injection_detector,
    llm_analyzer,
    scope_analyzer,
    sensitive_matcher,
)
from agentguard.engine.tool_normalizer import canonicalize_tool_name
from agentguard.models import (
    AuditLog,
    DataFlowReport,
    ExfiltrationRisk,
    InjectionReport,
    InstructionSource,
    LLMAnalysis,
    PolicyConfig,
    RiskLevel,
    SanitizedAction,
    ScopeAlignment,
    ScopeReport,
    SensitivityReport,
    ToolRequest,
    Verdict,
    VerdictType,
)

# In-memory audit store (production would use a database)
_audit_store: deque[Verdict] = deque(maxlen=1000)


def get_audit_log() -> List[Verdict]:
    """Return all stored verdicts."""
    return list(_audit_store)


def get_audit_entry(entry_id: str) -> Optional[Verdict]:
    """Return a single audit entry by ID."""
    for v in _audit_store:
        if v.id == entry_id:
            return v
    return None


def get_stats() -> Dict[str, Any]:
    """Return aggregate statistics."""
    total = len(_audit_store)
    verdicts = {"ALLOW": 0, "ASK_USER": 0, "DENY": 0}
    risks = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for v in _audit_store:
        verdicts[v.verdict.value] = verdicts.get(v.verdict.value, 0) + 1
        risks[v.risk_level.value] = risks.get(v.risk_level.value, 0) + 1
    return {"total": total, "verdicts": verdicts, "risk_levels": risks}


# ---------------------------------------------------------------------------
# Consequence / action-type classification
# ---------------------------------------------------------------------------

_SEND_TOOLS = {"send_email", "send_message", "reply_email", "forward_email"}
_EXECUTE_TOOLS = {"execute_command", "run_command", "run_shell", "shell",
                  "install_package", "curl", "wget"}
_DELETE_TOOLS = {"delete_file", "remove_file", "delete_email", "delete_event",
                 "delete_record", "unsubscribe", "revoke"}
_UPLOAD_TOOLS = {"upload_file", "browser_upload", "post_request", "http_post",
                 "publish"}
_FINANCIAL_TOOLS = {"transfer_funds", "make_purchase", "send_money"}

_FILE_READ_TOOLS = {"read_file", "view_file", "open_file", "get_file", "cat"}


def _highest_risk(*levels: RiskLevel) -> RiskLevel:
    """Return the highest risk level from the inputs."""
    order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    idx = max(order.index(l) for l in levels)
    return order[idx]


def _plain_message(verdict_type: VerdictType, tool: str, risk_factors: list[str],
                   safe_alt: Optional[str]) -> str:
    """Build a plain-English user message."""
    if verdict_type == VerdictType.ALLOW:
        return f"Action '{tool}' is within scope and safe to proceed."

    risk_text = "; ".join(risk_factors[:3]) if risk_factors else "potential risk detected"

    if verdict_type == VerdictType.DENY:
        msg = f"Blocked: the AI tried to use '{tool}'. Reason: {risk_text}."
        if safe_alt:
            msg += f" Safer alternative: {safe_alt}"
        return msg

    # ASK_USER
    msg = f"The AI wants to use '{tool}'. This needs your approval because: {risk_text}."
    if safe_alt:
        msg += f" Alternatively: {safe_alt}"
    return msg


# ---------------------------------------------------------------------------
# Main evaluation function — the 10-step procedure
# ---------------------------------------------------------------------------

def evaluate(request: ToolRequest) -> Verdict:
    """Evaluate a ToolRequest and return a Verdict.

    Implements the full 10-step reasoning procedure.
    """
    config = get_config()
    tool_lower = canonicalize_tool_name(request.tool)
    risk_factors: List[str] = []
    deterministic_checks: List[str] = []
    instruction_sources: List[InstructionSource] = []
    resource_targets: List[str] = []
    data_classes: List[str] = []

    # ----------------------------------------------------------------
    # STEP 1: NORMALIZE
    # ----------------------------------------------------------------
    args_text = json.dumps(request.arguments) if request.arguments else ""
    paths = sensitive_matcher.extract_paths_from_arguments(request.arguments)
    resource_targets.extend(paths)

    # ----------------------------------------------------------------
    # STEP 2: RECONSTRUCT USER SCOPE
    # ----------------------------------------------------------------
    scope_report: ScopeReport = scope_analyzer.analyze(
        user_goal=request.user_goal,
        tool=request.tool,
        action=request.action,
        arguments=request.arguments,
    )
    if request.source_content or request.context:
        instruction_sources.append(InstructionSource.MODEL_INFERENCE)
    instruction_sources.append(InstructionSource.EXPLICIT_USER_REQUEST)

    # ----------------------------------------------------------------
    # STEP 3: TEST NECESSITY (via scope report)
    # ----------------------------------------------------------------
    if scope_report.alignment == ScopeAlignment.OUT_OF_SCOPE:
        risk_factors.append("action is outside the scope of the user's request")
    elif scope_report.alignment == ScopeAlignment.AMBIGUOUS:
        risk_factors.append("action's relation to user's request is ambiguous")

    # ----------------------------------------------------------------
    # STEP 4: TEST SENSITIVITY
    # ----------------------------------------------------------------
    # 4a) Path sensitivity
    path_reports: List[SensitivityReport] = []
    for p in paths:
        pr = sensitive_matcher.check_path(p, config)
        path_reports.append(pr)
        if pr.is_sensitive:
            risk_factors.append(f"sensitive path detected: {p}")
            data_classes.extend(pr.categories)
            deterministic_checks.append("path_sensitivity_check")

    # 4b) Tool sensitivity
    tool_report = sensitive_matcher.check_tool(request.tool, request.action, config)
    if tool_report.is_sensitive:
        risk_factors.append(f"tool '{request.tool}' is classified as dangerous")
        deterministic_checks.append("tool_sensitivity_check")

    # 4c) Data-class sensitivity in arguments/context
    scan_text = " ".join(filter(None, [args_text, request.context, request.source_content]))
    data_report = sensitive_matcher.check_data_classes(scan_text, config)
    if data_report.is_sensitive:
        risk_factors.append("sensitive data classes detected in arguments/context")
        data_classes.extend(data_report.categories)
        deterministic_checks.append("data_class_check")

    # ----------------------------------------------------------------
    # STEP 5: TEST SOURCE AUTHORITY (prompt injection)
    # ----------------------------------------------------------------
    injection_report: InjectionReport = injection_detector.detect(
        source_content=request.source_content,
        context=request.context,
        arguments_text=args_text,
    )
    if injection_report.detected:
        risk_factors.append(
            f"prompt-injection indicators detected (confidence={injection_report.confidence})"
        )
        instruction_sources.append(InstructionSource.UNTRUSTED_CONTENT)
        deterministic_checks.append("injection_detection")

    # ----------------------------------------------------------------
    # STEP 6: TEST DATA FLOW
    # ----------------------------------------------------------------
    flow_report: DataFlowReport = dataflow_analyzer.analyze(
        tool=request.tool,
        action=request.action,
        arguments=request.arguments,
    )
    if flow_report.exfiltration_risk == ExfiltrationRisk.LIKELY:
        risk_factors.append("likely data exfiltration: sensitive source → external sink")
        deterministic_checks.append("dataflow_exfiltration_check")
    elif flow_report.exfiltration_risk == ExfiltrationRisk.POSSIBLE:
        risk_factors.append("possible data exfiltration risk")
        deterministic_checks.append("dataflow_exfiltration_check")

    # ----------------------------------------------------------------
    # STEP 7: TEST CONSEQUENCE
    # ----------------------------------------------------------------
    consequence_flags: list[str] = []
    if tool_lower in _SEND_TOOLS:
        consequence_flags.append("sends communication")
    if tool_lower in _EXECUTE_TOOLS:
        consequence_flags.append("executes code/commands")
    if tool_lower in _DELETE_TOOLS:
        consequence_flags.append("destructive/irreversible action")
    if tool_lower in _UPLOAD_TOOLS:
        consequence_flags.append("uploads/publishes data externally")
    if tool_lower in _FINANCIAL_TOOLS:
        consequence_flags.append("financial transaction")
    if consequence_flags:
        risk_factors.extend(consequence_flags)
        deterministic_checks.append("consequence_check")

    # ----------------------------------------------------------------
    # STEP 8: APPLY DETERMINISTIC RULES → compute overall risk
    # ----------------------------------------------------------------
    # Collect all risk levels from sub-reports
    all_risk_levels: List[RiskLevel] = [RiskLevel.LOW]
    for pr in path_reports:
        all_risk_levels.append(pr.risk_level)
    all_risk_levels.append(tool_report.risk_level)
    all_risk_levels.append(data_report.risk_level)
    if injection_report.detected and injection_report.confidence >= 0.5:
        all_risk_levels.append(RiskLevel.CRITICAL)
    elif injection_report.detected:
        all_risk_levels.append(RiskLevel.HIGH)
    if flow_report.exfiltration_risk == ExfiltrationRisk.LIKELY:
        all_risk_levels.append(RiskLevel.CRITICAL)
    elif flow_report.exfiltration_risk == ExfiltrationRisk.POSSIBLE:
        all_risk_levels.append(RiskLevel.MEDIUM)

    overall_risk = _highest_risk(*all_risk_levels)

    # ----------------------------------------------------------------
    # STEP 8.5: LLM DEEP ANALYSIS (if enabled)
    # ----------------------------------------------------------------
    llm_report = None  # type: Optional[LLMAnalysis]
    if config.llm_enabled:
        # Set API key from config if provided (env var takes precedence)
        import os
        if config.llm_api_key and not os.environ.get("OPENAI_API_KEY"):
            os.environ["OPENAI_API_KEY"] = config.llm_api_key

        llm_report = llm_analyzer.analyze(request, model=config.llm_model)
        if llm_report:
            risk_factors.append(f"LLM analysis: {llm_report.reasoning}")
            deterministic_checks.append("llm_deep_analysis")

            # LLM can escalate risk but never lower it
            llm_risk = llm_report.risk_level
            overall_risk = _highest_risk(overall_risk, llm_risk)

            # LLM scope assessment can override heuristic scope
            if llm_report.scope_alignment == ScopeAlignment.OUT_OF_SCOPE:
                if scope_report.alignment != ScopeAlignment.OUT_OF_SCOPE:
                    scope_report.alignment = ScopeAlignment.OUT_OF_SCOPE
                    scope_report.reasoning.append("LLM: action is out of scope")
            elif llm_report.scope_alignment == ScopeAlignment.AMBIGUOUS:
                if scope_report.alignment == ScopeAlignment.WITHIN_SCOPE:
                    scope_report.alignment = ScopeAlignment.AMBIGUOUS
                    scope_report.reasoning.append("LLM: scope alignment is ambiguous")

    # ----------------------------------------------------------------
    # STEP 9: DECIDE
    # ----------------------------------------------------------------
    verdict_type, safe_alternative = _decide(
        config=config,
        tool=request.tool,
        tool_lower=tool_lower,
        overall_risk=overall_risk,
        scope_report=scope_report,
        injection_report=injection_report,
        flow_report=flow_report,
        path_reports=path_reports,
        tool_report=tool_report,
        risk_factors=risk_factors,
        consequence_flags=consequence_flags,
    )

    # LLM escalation: LLM can push verdict UP but never DOWN
    if llm_report:
        _VERDICT_ORDER = [VerdictType.ALLOW, VerdictType.ASK_USER, VerdictType.DENY]
        llm_idx = _VERDICT_ORDER.index(llm_report.recommended_verdict)
        det_idx = _VERDICT_ORDER.index(verdict_type)
        if llm_idx > det_idx:
            verdict_type = llm_report.recommended_verdict
            if llm_report.safe_alternative:
                safe_alternative = llm_report.safe_alternative

    # ----------------------------------------------------------------
    # STEP 10: EXPLAIN
    # ----------------------------------------------------------------
    policy_summary = _policy_summary(verdict_type, risk_factors)
    user_message = _plain_message(verdict_type, request.tool, risk_factors, safe_alternative)
    detailed_reasoning = (
        scope_report.reasoning
        + [f"Injection: {', '.join(injection_report.matched_indicators)}" if injection_report.detected else "No injection indicators"]
        + flow_report.reasoning
        + risk_factors
    )

    # De-duplicate
    data_classes = list(dict.fromkeys(data_classes))
    deterministic_checks = list(dict.fromkeys(deterministic_checks))

    verdict = Verdict(
        verdict=verdict_type,
        risk_level=overall_risk,
        policy_summary=policy_summary,
        detailed_reasoning=detailed_reasoning,
        user_message=user_message,
        required_user_confirmation=(verdict_type == VerdictType.ASK_USER),
        safe_alternative=safe_alternative,
        sanitized_action=SanitizedAction(
            tool=request.tool if verdict_type != VerdictType.DENY else None,
            action=request.action if verdict_type != VerdictType.DENY else None,
            arguments=request.arguments if verdict_type == VerdictType.ALLOW else {},
        ),
        audit_log=AuditLog(
            user_goal=request.user_goal,
            requested_action=f"{request.tool}({request.action or ''})",
            resource_targets=resource_targets,
            data_classes=data_classes,
            source_of_instruction=instruction_sources,
            risk_factors=risk_factors,
            scope_alignment=scope_report.alignment,
            sensitivity_match=[
                p for pr in path_reports for p in pr.matched_patterns
            ] + tool_report.matched_patterns + data_report.matched_patterns,
            exfiltration_risk=flow_report.exfiltration_risk,
            deterministic_checks_used=deterministic_checks,
        ),
    )

    # Store for audit
    _audit_store.append(verdict)

    return verdict


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

def _decide(
    config: PolicyConfig,
    tool: str,
    tool_lower: str,
    overall_risk: RiskLevel,
    scope_report: ScopeReport,
    injection_report: InjectionReport,
    flow_report: DataFlowReport,
    path_reports: List[SensitivityReport],
    tool_report: SensitivityReport,
    risk_factors: List[str],
    consequence_flags: List[str],
) -> Tuple[VerdictType, Optional[str]]:
    """Core decision logic. Returns (verdict, safe_alternative)."""

    safe_alt = None  # type: Optional[str]

    # ---- Hard DENYs ----

    # Blocked tool
    if tool_report.categories and "blocked_tool" in tool_report.categories:
        return VerdictType.DENY, "Use a different tool that is not blocked by policy."

    # ANY injection indicators + sensitive path = DENY
    if injection_report.detected:
        for pr in path_reports:
            if pr.is_sensitive:
                return VerdictType.DENY, (
                    "This action appears to be driven by hidden instructions in content. "
                    "Only perform actions that the user explicitly requested."
                )
        if tool_report.is_sensitive and injection_report.confidence >= 0.5:
            return VerdictType.DENY, (
                "This action appears to be driven by hidden instructions in content. "
                "Only perform actions that the user explicitly requested."
            )

    # CRITICAL credential access — always DENY
    # Private keys, SSH keys, cloud creds should never be accessed for normal tasks
    for pr in path_reports:
        if pr.is_sensitive and pr.risk_level == RiskLevel.CRITICAL:
            if "credentials" in pr.categories:
                return VerdictType.DENY, "Only access files directly related to the user's request."

    # Likely exfiltration
    if flow_report.exfiltration_risk == ExfiltrationRisk.LIKELY:
        return VerdictType.DENY, (
            "Sensitive data should not be sent to external services without explicit user approval."
        )

    # Financial tools
    if tool_lower in _FINANCIAL_TOOLS:
        return VerdictType.ASK_USER, "Confirm the financial transaction details before proceeding."

    # ---- Consent-gated actions ----

    if tool_lower in _SEND_TOOLS and config.require_approval_for_send:
        return VerdictType.ASK_USER, "Draft the message without sending, then ask the user to review and send."

    if tool_lower in _EXECUTE_TOOLS and config.require_approval_for_execute:
        return VerdictType.ASK_USER, "Show the command to the user for review before executing."

    if tool_lower in _DELETE_TOOLS and config.require_approval_for_delete:
        return VerdictType.ASK_USER, "Confirm with the user which items to delete."

    if tool_lower in _UPLOAD_TOOLS and config.require_approval_for_external_upload:
        return VerdictType.ASK_USER, "Confirm the upload destination and file contents with the user."

    # ---- Sensitive path access (non-CRITICAL) ----
    for pr in path_reports:
        if pr.is_sensitive:
            if pr.risk_level == RiskLevel.HIGH:
                if scope_report.alignment == ScopeAlignment.OUT_OF_SCOPE:
                    return VerdictType.DENY, "Only access files the user explicitly requested."
                return VerdictType.ASK_USER, "Ask the user if they want to access this sensitive file."
            if scope_report.alignment != ScopeAlignment.WITHIN_SCOPE:
                return VerdictType.ASK_USER, "Confirm with the user before accessing this file."

    # ---- Injection with lower confidence (no sensitive path) ----
    if injection_report.detected:
        return VerdictType.ASK_USER, (
            "Possible prompt-injection detected in content. Confirm this action matches your intent."
        )

    # ---- Ambiguous scope ----
    if scope_report.alignment == ScopeAlignment.AMBIGUOUS and overall_risk != RiskLevel.LOW:
        return VerdictType.ASK_USER, "This action is not clearly within the user's request scope."

    # ---- Out of scope without other flags ----
    if scope_report.alignment == ScopeAlignment.OUT_OF_SCOPE:
        return VerdictType.ASK_USER, "This action appears outside the scope of the user's request."

    # ---- Overall risk check ----
    if overall_risk == RiskLevel.CRITICAL:
        return VerdictType.DENY, "This action is too risky to proceed without strong justification."
    if overall_risk == RiskLevel.HIGH:
        return VerdictType.ASK_USER, "This action carries significant risk. User should confirm."

    # ---- Default: ALLOW ----
    return VerdictType.ALLOW, None


def _policy_summary(verdict: VerdictType, risk_factors: list[str]) -> str:
    """One-sentence policy summary."""
    if verdict == VerdictType.ALLOW:
        return "Action is within user scope, non-sensitive, and safe to proceed."
    if verdict == VerdictType.DENY:
        top = risk_factors[0] if risk_factors else "policy violation"
        return f"Action blocked: {top}."
    top = risk_factors[0] if risk_factors else "action requires confirmation"
    return f"User confirmation required: {top}."
