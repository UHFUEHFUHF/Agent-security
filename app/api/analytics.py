from fastapi import APIRouter, Depends, Query
from app.api.deps import get_current_user
from app.db.mongo import get_db

router = APIRouter(tags=["analytics"])

@router.get("/metrics")
async def metrics(scope: str = Query("mine", pattern="^(mine|all)$"), user=Depends(get_current_user), db=Depends(get_db)):
    query = {} if scope == "all" and user["role"] == "admin" else {"owner_id": user["id"]}
    runs = [r async for r in db.runs.find(query, {"metrics": 1})]
    blocked = sum(r.get("metrics", {}).get("blocked_actions", 0) for r in runs)
    executed = sum(r.get("metrics", {}).get("executed_actions", 0) for r in runs)
    unauthorized = sum(r.get("metrics", {}).get("unauthorized_executions", 0) for r in runs)
    return {"runs": len(runs), "blocked_actions": blocked, "executed_actions": executed, "unauthorized_executions": unauthorized,
            "attack_block_rate": round(blocked / max(1, blocked + executed), 4),
            "scope": "all" if scope == "all" and user["role"] == "admin" else "mine"}

@router.get("/audit")
async def audit(scope: str = Query("mine", pattern="^(mine|all)$"), limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user), db=Depends(get_db)):
    query = {} if scope == "all" and user["role"] == "admin" else {"owner_id": user["id"]}
    items = []
    async for doc in db.audit_logs.find(query).sort("created_at", -1).limit(limit):
        doc["id"] = str(doc.pop("_id"))
        doc["created_at"] = doc["created_at"].isoformat()
        items.append(doc)
    return {"items": items}
