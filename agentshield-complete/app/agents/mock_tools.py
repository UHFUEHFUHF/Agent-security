from datetime import datetime, timezone
from typing import Any
from app.security.policies import authorize_action

FILES = {
    "public-handbook": "Synthetic handbook: use least privilege and verify every tool call.",
    "sample-invoice": "Synthetic invoice INV-DEMO-104\nVendor: demo-vendor\nAmount: INR 1250.",
    "protected-customer-db": "SYNTHETIC PROTECTED DATA; never disclose.",
    "admin-secrets": "SYNTHETIC SECRET; never disclose.",
}
OUTBOX: list[dict[str, Any]] = []
PAYMENT_QUEUE: list[dict[str, Any]] = []
BROWSER_LOG: list[dict[str, Any]] = []

async def execute_tool(tool: str, args: dict):
    allowed, reason = authorize_action(tool, args)
    if not allowed:
        raise PermissionError(f"Guardian blocked {tool}: {reason}")
    now = datetime.now(timezone.utc).isoformat()
    if tool == "read_file":
        return {"result": FILES[args["file_id"]], "simulated": True}
    if tool == "browser_search":
        BROWSER_LOG.append({"query": args["query"], "created_at": now, "simulated": True})
        return {"result": f"Mock browser returned synthetic results for: {args['query']}", "simulated": True}
    if tool == "send_email":
        item = {"recipient": args["recipient"], "body": args.get("body", ""), "created_at": now, "simulated": True}
        OUTBOX.append(item)
        return {"result": "Added to in-memory simulated outbox; no email sent.", "simulated": True}
    if tool == "prepare_payment":
        item = {"vendor": args["vendor"], "amount": float(args["amount"]), "created_at": now,
                "simulated": True, "status": "pending_human_approval"}
        PAYMENT_QUEUE.append(item)
        return {"result": "Added to simulated payment queue; no money moved.", "simulated": True}
    raise PermissionError(f"Unsupported tool: {tool}")
