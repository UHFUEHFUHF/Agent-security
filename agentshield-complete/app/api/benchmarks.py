"""Benchmark, replay, and per-user scoreboard endpoints for the synthetic arena."""
from datetime import datetime, timezone
from typing import Any
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from app.api.deps import get_current_user
from app.db.mongo import get_db
from app.services.runner import run_scenario, serialize_run
from app.agents.autonomous_red_team import generate_campaign
from app.api.autonomy import _judge
from app.security.adaptive_guardian import learn_from_training, load_latest_policy, persist_snapshot, active_policy

router = APIRouter(prefix="/benchmarks", tags=["benchmark-replay-scoreboard"])

class BenchmarkRequest(BaseModel):
    rounds: int = Field(default=3, ge=1, le=5)
    attacks_per_round: int = Field(default=6, ge=1, le=8)
    include_heldout: bool = True
    include_benign: bool = True

@router.post("/run")
async def run_benchmark(payload: BenchmarkRequest, user=Depends(get_current_user), db=Depends(get_db)):
    owner_id = user["id"]
    await load_latest_policy(db, owner_id)
    archive: set[str] = set()
    async for row in db.red_team_archive.find({"owner_id": owner_id}, {"fingerprint": 1}).limit(5000):
        if row.get("fingerprint"):
            archive.add(row["fingerprint"])
    rounds_out = []
    for round_no in range(1, payload.rounds + 1):
        cases = generate_campaign(round_no, payload.attacks_per_round, payload.include_benign,
                                  2 if payload.include_heldout else 0, archive)
        results = []
        for case in cases:
            run_doc = await run_scenario(db, user, case["scenario"], case["prompt"])
            run = serialize_run(run_doc)
            verdict = _judge(run, case)
            result = {"case_id": case["case_id"], "split": case["split"], "family": case["family"],
                      "objective": case["objective"], "scenario": case["scenario"],
                      "fingerprint": case["fingerprint"], "run_id": run.get("id"),
                      "trace_id": run.get("trace_id"), "verdict": verdict}
            results.append(result)
            await db.benchmark_case_results.insert_one({"owner_id": owner_id, "round": round_no, **result,
                                                        "created_at": datetime.now(timezone.utc)})
            await db.red_team_archive.update_one({"owner_id": owner_id, "fingerprint": case["fingerprint"]},
                {"$setOnInsert": {"owner_id": owner_id, "fingerprint": case["fingerprint"],
                 "family": case["family"], "first_seen_round": round_no, "split": case["split"],
                 "created_at": datetime.now(timezone.utc)}}, upsert=True)
        train_only = [r for r in results if r["split"] == "train"]
        feedback = await learn_from_training(db, owner_id, round_no, train_only)
        await persist_snapshot(db, owner_id, round_no)
        attacks = [r for r in results if r["objective"].startswith("A")]
        heldout = [r for r in results if r["split"] == "heldout" and r["objective"].startswith("A")]
        benign = [r for r in results if r["objective"] == "BENIGN_USEFULNESS"]
        success_count = sum(bool(r["verdict"]["attack_success"]) for r in attacks)
        summary = {"round": round_no, "case_count": len(results), "attack_cases": len(attacks),
            "attack_successes": success_count, "attack_success_rate": round(success_count / max(1, len(attacks)), 4),
            "heldout_cases": len(heldout), "heldout_block_rate": round(1 - sum(bool(r["verdict"]["attack_success"]) for r in heldout) / max(1, len(heldout)), 4),
            "benign_cases": len(benign), "usefulness_rate": round(sum(bool(r["verdict"]["benign_success"]) for r in benign) / max(1, len(benign)), 4),
            "protected_reads": sum(r["verdict"]["protected_reads"] for r in results),
            "canary_hits": sum(r["verdict"]["canary_hits"] for r in results),
            "unauthorized_effects": sum(r["verdict"]["unauthorized_effects"] for r in results),
            "guardian_version": active_policy()["version"], "guardian_feedback": feedback,
            "training_only_learning": True, "execution_mode": "SYNTHETIC_ONLY"}
        doc = {"owner_id": owner_id, "summary": summary, "cases": results,
               "created_at": datetime.now(timezone.utc), "execution_mode": "SYNTHETIC_ONLY"}
        inserted = await db.benchmark_runs.insert_one(doc)
        rounds_out.append({"id": str(inserted.inserted_id), "summary": summary, "cases": results})
    return {"status": "completed", "execution_mode": "SYNTHETIC_ONLY", "rounds": rounds_out,
            "disclaimer": "Prototype benchmark results are not a security certification; review traces and run tests."}

@router.get("/scoreboard")
async def scoreboard(limit: int = Query(20, ge=1, le=100), user=Depends(get_current_user), db=Depends(get_db)):
    rows = []
    async for doc in db.benchmark_runs.find({"owner_id": user["id"]}).sort("created_at", -1).limit(limit):
        rows.append({"id": str(doc["_id"]), "summary": doc.get("summary", {}),
                     "created_at": doc["created_at"].isoformat() if hasattr(doc.get("created_at"), "isoformat") else doc.get("created_at")})
    return {"items": rows, "scope": "current_user_only", "execution_mode": "SYNTHETIC_ONLY"}

@router.get("/history")
async def benchmark_history(limit: int = Query(20, ge=1, le=100), user=Depends(get_current_user), db=Depends(get_db)):
    return await scoreboard(limit, user, db)

@router.get("/replay/{run_id}")
async def replay_trace(run_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    if not ObjectId.is_valid(run_id):
        raise HTTPException(status_code=400, detail="Invalid run id")
    query: dict[str, Any] = {"_id": ObjectId(run_id)}
    if user.get("role") != "admin":
        query["owner_id"] = user["id"]
    run = await db.runs.find_one(query)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    run = serialize_run(run)
    actions = run.get("actions", [])
    timeline = [{"sequence": i + 1, "trace_id": a.get("trace_id"), "tool": a.get("tool"),
                 "allowed": a.get("allowed"), "executed": a.get("executed"), "reason": a.get("reason"),
                 "risk": a.get("risk"), "policy": a.get("guardian_policy"), "provenance": a.get("provenance")}
                for i, a in enumerate(actions)]
    return {"run_id": run["id"], "trace_id": run.get("trace_id"), "scenario": run.get("scenario"),
            "execution_mode": "READ_ONLY_REPLAY", "timeline": timeline, "metrics": run.get("metrics", {}),
            "note": "Replay displays recorded decisions; it does not re-execute tools."}
