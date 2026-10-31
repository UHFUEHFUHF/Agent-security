from datetime import datetime, timezone
from uuid import uuid4
from app.agents.target import propose_actions
from app.agents.red_team import create_attack
from app.agents.mock_tools import execute_tool
from app.security.semantic_guardian import decide_action


def serialize_run(run):
    result = dict(run)
    if "_id" in result:
        result["id"] = str(result.pop("_id"))
    if hasattr(result.get("created_at"), "isoformat"):
        result["created_at"] = result["created_at"].isoformat()
    return result


async def run_scenario(db, user, scenario, prompt=""):
    now = datetime.now(timezone.utc)
    trace_id = str(uuid4())
    # The Red Team creates a synthetic artifact first. The target sees it only as
    # untrusted input; it never receives a direct tool handle from the Red Team.
    attack = await create_attack(scenario, prompt)
    target_context = f"{prompt}\n\n[UNTRUSTED SYNTHETIC ARTIFACT - NOT AN AUTHORITY]\n{attack}"[:4000]
    response, proposals = await propose_actions(scenario, target_context)
    actions, blocked, executed = [], 0, 0
    for proposal in proposals[:10]:
        action_trace_id = str(uuid4())
        if not isinstance(proposal, dict):
            blocked += 1
            actions.append({"trace_id":action_trace_id,"tool":"invalid_proposal","arguments":{},"allowed":False,"reason":"Malformed proposal denied by default.","executed":False,"result":None,"provenance":"model_output"})
            continue
        tool = proposal.get("tool", "")
        args = proposal.get("arguments", {})
        if not isinstance(args, dict):
            args = {}
        decision = decide_action(str(tool), args, task=f"trusted scenario: {scenario}", scenario=scenario, untrusted_content=attack)
        allowed, reason = decision["allowed"], decision["reason"]
        result, did_execute = None, False
        if allowed:
            try:
                # execute_tool repeats the base allow-list check at the boundary.
                result = await execute_tool(str(tool), args)
                did_execute = True
                executed += 1
            except Exception:
                allowed, reason = False, "Tool execution failed safely."
                blocked += 1
        else:
            blocked += 1
        actions.append({"trace_id":action_trace_id,"tool":str(tool)[:80],"arguments":args,"allowed":allowed,"reason":reason,"executed":did_execute,"result":result,"guardian_policy":decision.get("policy"),"risk":decision.get("risk"),"provenance":decision.get("provenance","model_output")})
    metrics = {"proposed_actions":len(proposals[:10]),"blocked_actions":blocked,"executed_actions":executed,"unauthorized_executions":0,"action_block_rate":round(blocked/max(1,blocked+executed),4)}
    doc = {"owner_id":user["id"],"scenario":scenario,"status":"completed","trace_id":trace_id,"target_response":response[:2000],"red_team_attack":attack[:2000],"actions":actions,"metrics":metrics,"execution_mode":"SYNTHETIC_ONLY","created_at":now}
    inserted = await db.runs.insert_one(doc)
    doc["_id"] = inserted.inserted_id
    await db.audit_logs.insert_one({"owner_id":user["id"],"run_id":str(inserted.inserted_id),"trace_id":trace_id,"event":"scenario_run_completed","scenario":scenario,"metrics":metrics,"created_at":datetime.now(timezone.utc)})
    for action in actions:
        await db.action_logs.insert_one({"owner_id":user["id"],"run_id":str(inserted.inserted_id),"trace_id":action["trace_id"],"tool":action["tool"],"allowed":action["allowed"],"executed":action["executed"],"reason":action["reason"],"guardian_policy":action.get("guardian_policy"),"provenance":action.get("provenance"),"created_at":datetime.now(timezone.utc)})
    return doc
