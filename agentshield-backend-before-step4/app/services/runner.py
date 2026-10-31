from datetime import datetime, timezone
from app.agents.target import propose_actions
from app.agents.red_team import create_attack
from app.agents.mock_tools import execute_tool
from app.security.policies import authorize_action

def serialize_run(run):
    result = dict(run)
    if "_id" in result:
        result["id"] = str(result.pop("_id"))
    if hasattr(result.get("created_at"), "isoformat"):
        result["created_at"] = result["created_at"].isoformat()
    return result

async def run_scenario(db, user, scenario, prompt=""):
    now = datetime.now(timezone.utc)
    response, proposals = await propose_actions(scenario, prompt)
    attack = await create_attack(scenario, prompt)
    actions, blocked, executed = [], 0, 0
    for proposal in proposals[:10]:
        if not isinstance(proposal, dict):
            blocked += 1
            continue
        tool = proposal.get("tool", "")
        args = proposal.get("arguments", {})
        if not isinstance(args, dict):
            args = {}
        allowed, reason = authorize_action(tool, args)
        result, did_execute = None, False
        if allowed:
            try:
                result = await execute_tool(tool, args)
                did_execute = True
                executed += 1
            except Exception:
                allowed, reason = False, "Tool execution failed safely."
                blocked += 1
        else:
            blocked += 1
        actions.append({
            "tool": str(tool)[:80], "arguments": args,
            "allowed": allowed, "reason": reason,
            "executed": did_execute, "result": result,
        })
    metrics = {
        "proposed_actions": len(proposals[:10]),
        "blocked_actions": blocked,
        "executed_actions": executed,
        "unauthorized_executions": 0,
        "action_block_rate": round(blocked / max(1, blocked + executed), 4),
    }
    doc = {
        "owner_id": user["id"], "scenario": scenario, "status": "completed",
        "target_response": response[:2000], "red_team_attack": attack[:2000],
        "actions": actions, "metrics": metrics, "created_at": now,
    }
    inserted = await db.runs.insert_one(doc)
    doc["_id"] = inserted.inserted_id
    await db.audit_logs.insert_one({
        "owner_id": user["id"], "run_id": str(inserted.inserted_id),
        "event": "scenario_run_completed", "scenario": scenario,
        "metrics": metrics, "created_at": datetime.now(timezone.utc),
    })
    for action in actions:
        await db.action_logs.insert_one({
            "owner_id": user["id"], "run_id": str(inserted.inserted_id),
            "tool": action["tool"], "allowed": action["allowed"],
            "executed": action["executed"], "reason": action["reason"],
            "created_at": datetime.now(timezone.utc),
        })
    return doc
