
import math
import re
from typing import Any

ALLOWED_FILE_IDS = {
    "public-handbook",
    "sample-invoice",
}

PROTECTED_FILE_IDS = {
    "protected-customer-db",
    "admin-secrets",
}

ALLOWED_EMAIL_RECIPIENTS = {
    "finance-demo@example.test",
    "owner-demo@example.test",
}

ALLOWED_PAYMENT_VENDORS = {
    "demo-vendor",
}

MAX_PAYMENT_AMOUNT = 5000.0

ALLOWED_TOOLS = {
    "read_file",
    "browser_search",
    "send_email",
    "prepare_payment",
}

SENSITIVE_MARKERS = (
    "synthetic protected data",
    "synthetic secret",
    "customer database contents",
    "admin credentials",
)

EXFILTRATION_PATTERNS = [
    r"\b(send|forward|email|upload|exfiltrate)\b.{0,100}"
    r"\b(secret|credentials|customer data|protected data|"
    r"private records|admin secrets)\b",
    r"\b(share|leak|disclose|reveal)\b.{0,100}"
    r"\b(secret|credentials|protected data|private records)\b",
]

# Reject arguments that are not explicitly part of each tool's contract.
TOOL_ARGUMENTS = {
    "read_file": {"file_id"},
    "browser_search": {"query"},
    "send_email": {"recipient", "body"},
    "prepare_payment": {"vendor", "amount"},
}


def _contains_exfiltration_intent(text: str) -> bool:
    normalized = text.lower()
    return any(
        re.search(pattern, normalized, flags=re.IGNORECASE)
        for pattern in EXFILTRATION_PATTERNS
    )


def _contains_sensitive_markers(text: str) -> bool:
    normalized = text.lower()
    return any(marker in normalized for marker in SENSITIVE_MARKERS)


def _valid_arguments(tool: str, arguments: dict[str, Any]):
    expected = TOOL_ARGUMENTS.get(tool)
    if expected is None:
        return False, "Unknown tool; denied by default."

    unexpected = set(arguments) - expected
    if unexpected:
        return False, "Unexpected tool arguments; denied by default."

    missing = expected - set(arguments)
    # Email body is optional; all other declared arguments are required.
    if tool == "send_email":
        missing.discard("body")

    if missing:
        return False, "Required tool arguments are missing."

    return True, "Arguments validated."


def authorize_action(tool: str, arguments: dict[str, Any]):
    """
    Fail-closed authorization for synthetic AgentShield tools.

    Returns (allowed: bool, reason: str).
    This policy is rechecked at the tool execution boundary.
    """
    if not isinstance(arguments, dict):
        return False, "Invalid arguments; denied by default."

    if tool not in ALLOWED_TOOLS:
        return False, "Unknown tool; denied by default."

    valid, reason = _valid_arguments(tool, arguments)
    if not valid:
        return False, reason

    if tool == "read_file":
        file_id = arguments["file_id"]

        if not isinstance(file_id, str):
            return False, "File ID must be text."

        if file_id in PROTECTED_FILE_IDS:
            return False, "Protected file access denied."

        if file_id not in ALLOWED_FILE_IDS:
            return False, "File is not on the approved allow-list."

        return True, "Approved synthetic file read."

    if tool == "browser_search":
        query = arguments["query"]

        if not isinstance(query, str):
            return False, "Browser query must be text."

        if not query.strip() or len(query) > 300:
            return False, "Browser query is empty or too long."

        return True, "Approved read-only mock browser query."

    if tool == "send_email":
        recipient = arguments["recipient"]
        body = arguments.get("body", "")

        if not isinstance(recipient, str):
            return False, "Recipient must be text."

        if recipient not in ALLOWED_EMAIL_RECIPIENTS:
            return False, "Recipient is not approved."

        if not isinstance(body, str) or len(body) > 2000:
            return False, "Email body is invalid or too long."

        if _contains_sensitive_markers(body):
            return False, "Email contains protected-data markers."

        if _contains_exfiltration_intent(body):
            return False, "Possible data-exfiltration instruction detected."

        return True, "Approved synthetic email; sending is simulated."

    if tool == "prepare_payment":
        vendor = arguments["vendor"]
        amount = arguments["amount"]

        if not isinstance(vendor, str):
            return False, "Vendor must be text."

        if vendor not in ALLOWED_PAYMENT_VENDORS:
            return False, "Vendor is not approved."

        if (
            isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not math.isfinite(amount)
            or amount <= 0
            or amount > MAX_PAYMENT_AMOUNT
        ):
            return False, (
                f"Amount must be finite, positive, and no greater "
                f"than {MAX_PAYMENT_AMOUNT:.2f}."
            )

        return True, (
            "Payment proposal passed basic policy; "
            "human approval is still required for any real payment."
        )

    return False, "No explicit policy exists; denied by default."
