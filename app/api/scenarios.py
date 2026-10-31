from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from app.api.deps import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.db.models import User, Run
from app.schemas import ScenarioRequest, BatchScenarioRequest
from app.services.runner import run_scenario
from app.services.evaluation import calculate_metrics

router = APIRouter(tags=["Scenarios and Evaluation"])

def serialize(run):
    return {"id": run.id, "owner_id": run.owner_id, "scenario_type": run.scenario_type, "task": run.task,
            "status": run.status, "used_llm": run.used_llm, "attack_detected": run.attack_detected,
            "attack_blocked": run.attack_blocked, "legitimate_task_success": run.legitimate_task_success,
            "unauthorized_execution_count": run.unauthorized_execution_count, "summary": run.summary,
            "metrics": run.metrics, "created_at": run.created_at,
            "actions": [{"id": a.id, "tool_name": a.tool_name, "arguments": a.arguments,
                         "decision": a.decision, "reason": a.reason, "result": a.result, "created_at": a.created_at}
                        for a in run.actions]}

@router.post("/scenarios/run")
def run_one(payload: ScenarioRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return serialize(run_scenario(db, user, payload))

@router.post("/scenarios/batch")
def run_batch(payload: BatchScenarioRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if len(payload.scenarios) > settings.max_batch_scenarios:
        raise HTTPException(status_code=422, detail=f"Maximum batch size is {settings.max_batch_scenarios}")
    return [serialize(run_scenario(db, user, s)) for s in payload.scenarios]

@router.get("/runs")
def list_runs(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
              db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Run).options(joinedload(Run.actions))
    if user.role != "admin":
        q = q.filter(Run.owner_id == user.id)
    return [serialize(r) for r in q.order_by(Run.id.desc()).offset(offset).limit(limit).all()]

@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    run = db.query(Run).options(joinedload(Run.actions)).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot access another user's run")
    return serialize(run)

@router.get("/metrics")
def metrics(scope: str = Query("mine", pattern="^(mine|all)$"), db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    q = db.query(Run).options(joinedload(Run.actions))
    if scope == "all":
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin role required for all-user metrics")
    else:
        q = q.filter(Run.owner_id == user.id)
    return calculate_metrics(q.all())
