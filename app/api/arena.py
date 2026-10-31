from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_current_user
from app.db.mongo import get_db
from app.services.runner import run_scenario, serialize_run
from app.services.arena_engine import TRAIN_CASES, HELDOUT_CASES, judge_run, summarize_round, update_guardian_from_training

router = APIRouter(prefix="/arena", tags=["red-team-arena"])

class ArenaRequest(BaseModel):
    rounds: int = Field(default=3, ge=1, le=5)
    attacks_per_round: int = Field(default=4, ge=1, le=8)
    include_heldout: bool = True

@router.post("/run")
async def run_arena(payload: ArenaRequest, user=Depends(get_current_user), db=Depends(get_db)):
    round_results = []
    for round_number in range(1, payload.rounds + 1):
        # Deterministic rotation adds variety each round. Held-out cases are only
        # evaluated; the training updater receives train records exclusively.
        offset = ((round_number - 1) * payload.attacks_per_round) % len(TRAIN_CASES)
        ordered_train = TRAIN_CASES[offset:] + TRAIN_CASES[:offset]
        cases = ordered_train[:payload.attacks_per_round]
        if payload.include_heldout:
            cases += HELDOUT_CASES[:min(2, len(HELDOUT_CASES))]
        results = []
        for case in cases:
            try:
                run = serialize_run(await run_scenario(db, user, case["scenario"], case["prompt"]))
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Arena case {case['id']} failed safely.") from exc
            verdict = judge_run({**run, "benchmark_metadata":[{"objective":case["objective"]}]})
            split = "heldout" if case["id"].startswith("heldout-") else "train"
            item = {"case_id":case["id"],"split":split,"objective":case["objective"],"family":case["family"],"scenario":case["scenario"],"run_id":run["id"],"trace_id":run.get("trace_id"),"verdict":verdict}
            await db.arena_case_results.insert_one({"owner_id":user["id"],"round":round_number,**item,"created_at":datetime.now(timezone.utc)})
            results.append(item)
        feedback = await update_guardian_from_training(db, user["id"], round_number, results)
        summary = summarize_round(round_number, results)
        summary["guardian_feedback"] = feedback
        round_doc = {"owner_id":user["id"],"round":round_number,"summary":summary,"cases":results,"execution_mode":"SYNTHETIC_ONLY","created_at":datetime.now(timezone.utc)}
        inserted = await db.arena_rounds.insert_one(round_doc)
        round_results.append({"id":str(inserted.inserted_id),"summary":summary,"cases":results})
    return {"status":"completed","execution_mode":"SYNTHETIC_ONLY","rounds":round_results,"note":"Train-only feedback is recorded; held-out examples are excluded from feedback. Policy rules are not automatically weakened or rewritten."}

@router.get("/history")
async def arena_history(limit: int = 20, user=Depends(get_current_user), db=Depends(get_db)):
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
    items = []
    async for doc in db.arena_rounds.find({"owner_id":user["id"]}).sort("created_at",-1).limit(limit):
        doc["id"] = str(doc.pop("_id"))
        if hasattr(doc.get("created_at"),"isoformat"):
            doc["created_at"] = doc["created_at"].isoformat()
        summary = doc.get("summary")
        if isinstance(summary, dict):
            feedback = summary.get("guardian_feedback")
            if isinstance(feedback, dict):
                feedback.pop("_id", None)
        items.append(doc)
    return {"items":items}

@router.get("/replay/{run_id}")
async def replay_run(run_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    from bson import ObjectId
    if not ObjectId.is_valid(run_id):
        raise HTTPException(status_code=400, detail="Invalid run id")
    run = await db.runs.find_one({"_id":ObjectId(run_id),"owner_id":user["id"]})
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return serialize_run(run)


#hello