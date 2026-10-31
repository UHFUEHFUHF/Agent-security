from fastapi import APIRouter, Depends, HTTPException
from bson import ObjectId
from app.api.deps import require_admin
from app.db.mongo import get_db
from app.schemas import RoleUpdate

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/users")
async def list_users(_admin=Depends(require_admin), db=Depends(get_db)):
    items = []
    async for u in db.users.find({}, {"email": 1, "role": 1, "disabled": 1, "created_at": 1}).sort("created_at", -1).limit(200):
        items.append({"id": str(u["_id"]), "email": u["email"], "role": u["role"], "disabled": u.get("disabled", False), "created_at": u["created_at"].isoformat()})
    return {"items": items}

@router.patch("/users/{user_id}/role")
async def update_role(user_id: str, payload: RoleUpdate, admin=Depends(require_admin), db=Depends(get_db)):
    if not ObjectId.is_valid(user_id):
        raise HTTPException(400, "Invalid user id")
    if admin["id"] == user_id and payload.role != "admin":
        raise HTTPException(400, "Admins cannot demote themselves")
    result = await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": payload.role}})
    if not result.matched_count:
        raise HTTPException(404, "User not found")
    return {"message": "Role updated", "user_id": user_id, "role": payload.role}
