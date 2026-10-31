from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.db.mongo import get_db
from app.schemas import ScenarioRunRequest, BatchRunRequest
from app.services.runner import run_scenario, serialize_run

router = APIRouter(prefix="/scenarios", tags=["scenarios"])

@router.post("/run")
async def run_one(payload: ScenarioRunRequest, user=Depends(get_current_user), db=Depends(get_db)):
    return serialize_run(await run_scenario(db, user, payload.scenario, payload.prompt))

@router.post("/batch")
async def run_batch(payload: BatchRunRequest, user=Depends(get_current_user), db=Depends(get_db)):
    return {"items": [serialize_run(await run_scenario(db, user, scenario, "")) for scenario in payload.scenarios]}
