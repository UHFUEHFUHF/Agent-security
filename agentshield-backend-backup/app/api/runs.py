from fastapi import APIRouter, Depends, HTTPException, Query
from bson import ObjectId
from app.api.deps import get_current_user
from app.db.mongo import get_db

router = APIRouter(tags=["runs"])

def clean(doc):
    doc["id"] = str(doc.pop("_id"))
    if hasattr(doc.get("created_at"), "isoformat"):
        doc["created_at"] = doc["created_at"].isoformat()
    return doc

@router.get("/runs")
async def list_runs(limit: int = Query(20, ge=1, le=100), user=Depends(get_current_user), db=Depends(get_db)):
    return {"items": [clean(d) async for d in db.runs.find({"owner_id": user["id"]}).sort("created_at", -1).limit(limit)]}

@router.get("/runs/{run_id}")
async def get_run(run_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    if not ObjectId.is_valid(run_id):
        raise HTTPException(400, "Invalid run id")
    query = {"_id": ObjectId(run_id)}
    if user["role"] != "admin":
        query["owner_id"] = user["id"]
    doc = await db.runs.find_one(query)
    if not doc:
        raise HTTPException(404, "Run not found")
    return clean(doc)
