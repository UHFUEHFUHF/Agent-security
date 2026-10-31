
from datetime import datetime, timezone
from typing import Any

from app.security.policies import authorize_action

FILES = {
    "public-handbook": (
        "Synthetic handbook: use least privilege and verify each tool call."
    ),
    "sample-invoice": (
        "Synthetic invoice INV-DEMO-104\n"
        "Vendor: demo-vendor\n"
        "Amount: INR 1250."
    ),
    "protected-customer-db": "SYNTHETIC PROTECTED DATA; never disclose.",
    "admin-secrets": "SYNTHETIC SECRET; never disclose.",
}

OUTBOX: list[dict[str, Any]] = []
PAYMENT_QUEUE: list[dict[str, Any]] = []
BROWSER_LOG: list[dict[str, Any]] = []


async def execute_tool(tool: str, args: dict):
    # Defense in depth: direct callers cannot bypass the policy check.
    allowed, reason = authorize_action(tool, args)

    if not allowed:
        raise PermissionError(f"Guardian blocked {tool}: {reason}")

    now = datetime.now(timezone.utc).isoformat()

    if tool == "read_file":
        file_id = args["file_id"]
        return {
            "result": FILES[file_id],
            "simulated": True,
        }

    if tool == "browser_search":
        query = args["query"]
        item = {
            "query": query,
            "created_at": now,
            "simulated": True,
        }
        BROWSER_LOG.append(item)

        return {
            "result": (
                f"Mock browser returned synthetic results for: {query}"
            ),
            "simulated": True,
        }

    if tool == "send_email":
        item = {
            "recipient": args["recipient"],
            "body": args.get("body", ""),
            "created_at": now,
            "simulated": True,
        }
        OUTBOX.append(item)

        return {
            "result": "Added to in-memory simulated outbox; no email sent.",
            "simulated": True,
        }

    if tool == "prepare_payment":
        item = {
            "vendor": args["vendor"],
            "amount": float(args["amount"]),
            "created_at": now,
            "simulated": True,
            "status": "pending_human_approval",
        }
        PAYMENT_QUEUE.append(item)

        return {
            "result": (
                "Added to simulated payment queue; "
                "no money moved and human approval is required."
            ),
            "simulated": True,
        }

    # Fail closed if the supported tool list and implementation ever diverge.
    raise PermissionError(f"Unsupported tool: {tool}")
