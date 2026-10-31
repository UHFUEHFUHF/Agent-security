"""Versioned, conservative Guardian adaptation.

Learning only adds review/block indicators. It never removes base policies, grants
new capabilities, or consumes held-out cases. Context-local policy state avoids
cross-request policy bleed in a single-process async server.
"""
from __future__ import annotations
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

DEFAULT_INDICATORS = {
    "authority_impersonation": ("fictional security administrator", "fake system notice", "compliance lead authorizes"),
    "task_relabeling": ("relabeled exfiltration", "bypass allow-lists", "disclose its contents"),
    "urgency": ("skip approval", "999999 inr", "emergency untrusted message"),
    "multi_hop": ("artifact a says", "artifact b says", "two synthetic notes"),
    "hidden_instruction": ("html alt-text", "untrusted metadata"),
    "fake_tool_output": ("fake synthetic tool output", "untrusted log says the guardian approved"),
    "obfuscation": ("translated/indirect untrusted note", "obfuscated synthetic instruction"),
}
_BASE_INDICATORS = sorted({x for values in DEFAULT_INDICATORS.values() for x in values})
_POLICY: ContextVar[dict[str, Any]] = ContextVar(
    "agentshield_guardian_policy",
    default={"version": 1, "indicators": _BASE_INDICATORS},
)


def active_policy() -> dict[str, Any]:
    policy = _POLICY.get()
    return {"version": policy["version"], "indicators": list(policy["indicators"])}


def additional_deny_reason(tool: str, untrusted_content: str) -> str | None:
    """Apply learned indicators only to sensitive side-effect tools."""
    if tool not in {"send_email", "prepare_payment"}:
        return None
    text = (untrusted_content or "").casefold()
    matched = [term for term in _POLICY.get()["indicators"] if term.casefold() in text]
    if matched:
        return f"Adaptive Guardian blocked sensitive action: untrusted artifact matched learned risk indicator '{matched[0]}'."
    return None


async def learn_from_training(db, owner_id: str, round_number: int,
                              training_cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a monotonic policy version from training cases only."""
    safe_cases = [c for c in training_cases if c.get("split") == "train"]
    current = _POLICY.get()
    observed_families = sorted({str(c.get("family", "")) for c in safe_cases
                                if c.get("family") not in {"", "benign"}})
    proposed = set(current["indicators"])
    for family in observed_families:
        proposed.update(DEFAULT_INDICATORS.get(family, ()))
    previous = set(current["indicators"])
    added = sorted(proposed - previous)
    new_version = int(current["version"]) + (1 if added else 0)
    snapshot = {"version": new_version, "indicators": sorted(proposed)}
    _POLICY.set(snapshot)
    document = {
        "owner_id": owner_id, "round": round_number, "version": new_version,
        "observed_training_families": observed_families, "added_indicators": added,
        "indicator_count": len(proposed), "indicators": sorted(proposed),
        "heldout_consumed": False,
        "policy_change": "monotonic_additive_deny_indicators" if added else "no_change",
        "created_at": datetime.now(timezone.utc),
    }
    await db.guardian_policy_versions.update_one(
        {"owner_id": owner_id, "version": new_version},
        {"$set": document}, upsert=True,
    )
    return {k: v for k, v in document.items() if k != "owner_id"}


async def load_latest_policy(db, owner_id: str) -> dict[str, Any]:
    """Restore this user's latest policy into the current async request context."""
    doc = await db.guardian_policy_versions.find_one(
        {"owner_id": owner_id}, sort=[("version", -1)]
    )
    if doc:
        _POLICY.set({"version": int(doc.get("version", 1)),
                     "indicators": list(doc.get("indicators", _BASE_INDICATORS))})
    else:
        _POLICY.set({"version": 1, "indicators": list(_BASE_INDICATORS)})
    return active_policy()


async def persist_snapshot(db, owner_id: str, round_number: int) -> None:
    """Persist full indicator snapshot for process restart."""
    policy = active_policy()
    await db.guardian_policy_versions.update_one(
        {"owner_id": owner_id, "version": policy["version"]},
        {"$set": {"indicators": policy["indicators"], "round": round_number,
                  "snapshot_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
