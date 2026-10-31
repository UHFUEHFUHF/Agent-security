from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.api.deps import get_current_user
from app.db.session import get_db
from app.db.models import User, AuditEvent, Run

router = APIRouter(tags=["Audit"])

@router.get("/audit")
def audit(scope: str = Query("mine", pattern="^(mine|all)$"), limit: int = Query(100, ge=1, le=500),
          db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if scope == "all" and user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    q = db.query(AuditEvent)
    if scope == "mine":
        ids = [str(row[0]) for row in db.query(Run.id).filter(Run.owner_id == user.id).all()]
        q = q.filter((AuditEvent.actor_user_id == user.id) |
                     ((AuditEvent.resource_type == "run") & (AuditEvent.resource_id.in_(ids))))
    return [{"id": e.id, "actor_user_id": e.actor_user_id, "event_type": e.event_type,
             "resource_type": e.resource_type, "resource_id": e.resource_id, "details": e.details,
             "created_at": e.created_at} for e in q.order_by(AuditEvent.id.desc()).limit(limit).all()]
