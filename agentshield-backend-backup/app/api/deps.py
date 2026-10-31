import jwt
from bson import ObjectId
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.db.mongo import get_db
from app.security.tokens import decode_access_token

bearer = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db=Depends(get_db)):
    if credentials is None:
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_access_token(credentials.credentials)
        if not ObjectId.is_valid(payload.get("sub", "")):
            raise ValueError("Invalid subject")
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user or user.get("disabled", False):
        raise HTTPException(401, "Account unavailable")
    user["id"] = str(user.pop("_id"))
    return user

async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin role required")
    return user
