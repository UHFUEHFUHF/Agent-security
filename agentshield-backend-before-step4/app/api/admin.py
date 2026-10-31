from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import require_admin
from app.db.session import get_db
from app.db.models import User, AuditEvent
from app.schemas import UserOut, RoleUpdate

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.id).all()

@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_role(user_id: int, payload: RoleUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot remove your own admin role")
    old = user.role
    user.role = payload.role
    db.add(AuditEvent(actor_user_id=admin.id, event_type="admin.role_changed", resource_type="user",
                      resource_id=str(user.id), details={"from": old, "to": payload.role}))
    db.commit()
    db.refresh(user)
    return user
