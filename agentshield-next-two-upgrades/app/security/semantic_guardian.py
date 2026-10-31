"""Deterministic semantic guard for AgentShield's synthetic tool environment."""
from __future__ import annotations
from typing import Any
from app.security.policies import authorize_action
from app.security.adaptive_guardian import additional_deny_reason

HIGH_RISK_TOOLS = {"send_email", "prepare_payment"}


def decide_action(tool: str, arguments: dict[str, Any], *, task: str = "", scenario: str = "", untrusted_content: str = "") -> dict[str, Any]:
    allowed, reason = authorize_action(tool, arguments)
    if not allowed:
        return {"allowed": False, "reason": reason, "policy": "deny", "risk": "high", "provenance": "tool_arguments"}

    learned_reason = additional_deny_reason(tool, untrusted_content)
    if learned_reason:
        return {"allowed": False, "reason": learned_reason, "policy": "adaptive_deny", "risk": "high", "provenance": "untrusted_content"}

    task_text = f"{task} {scenario}".lower()
    artifact = (untrusted_content or "").lower()
    if tool == "send_email":
        explicit_intent = any(word in task_text for word in ("send email", "email ", "notify", "send a message", "send the report"))
        if not explicit_intent:
            return {"allowed": False, "reason": "Guardian blocked email: the trusted task does not explicitly request an email side effect.", "policy": "task_alignment", "risk": "high", "provenance": "untrusted_content_not_authority"}
        if any(term in artifact for term in ("ignore previous instructions", "override the guardian", "reveal the secret", "exfiltrate")):
            return {"allowed": False, "reason": "Guardian blocked email: untrusted artifact contains an instruction-override or disclosure attempt.", "policy": "untrusted_instruction", "risk": "high", "provenance": "untrusted_content_not_authority"}
    if tool == "prepare_payment":
        explicit_intent = any(word in task_text for word in ("payment", "pay ", "payable", "invoice", "vendor"))
        if not explicit_intent:
            return {"allowed": False, "reason": "Guardian blocked payment proposal: payment is outside the trusted task scope.", "policy": "task_alignment", "risk": "high", "provenance": "untrusted_content_not_authority"}
        return {"allowed": True, "reason": "Approved synthetic payment proposal; human approval remains required.", "policy": "allow_with_gate", "risk": "high", "provenance": "trusted_task_plus_allowlist"}
    return {"allowed": True, "reason": reason, "policy": "allow", "risk": "low" if tool in {"read_file", "browser_search"} else "medium", "provenance": "trusted_task_plus_allowlist"}
