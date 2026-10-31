from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pymongo.errors import DuplicateKeyError
from app.db.mongo import get_db
from app.schemas import RegisterRequest, LoginRequest, UserOut, TokenOut
from app.security.passwords import hash_password, verify_password
from app.security.tokens import create_access_token
from app.api.deps import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["authentication"])

def public_user(user):
    return UserOut(id=str(user.get("id", user.get("_id"))), email=user["email"], role=user["role"], created_at=user["created_at"].isoformat())

@router.post("/register", response_model=TokenOut, status_code=201)
async def register(payload: RegisterRequest, db=Depends(get_db)):
    email = payload.email.lower().strip()
    role = "admin" if settings.bootstrap_admin_email and email == settings.bootstrap_admin_email.lower().strip() else "user"
    user = {"email": email, "password_hash": hash_password(payload.password), "role": role, "disabled": False, "created_at": datetime.now(timezone.utc)}
    try:
        result = await db.users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(409, "An account with this email already exists")
    user["id"] = str(result.inserted_id)
    token, expires = create_access_token(user["id"], role)
    return TokenOut(access_token=token, expires_in=expires, user=public_user(user))

@router.post("/login", response_model=TokenOut)
async def login(payload: LoginRequest, db=Depends(get_db)):
    user = await db.users.find_one({"email": payload.email.lower().strip()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")) or user.get("disabled", False):
        raise HTTPException(401, "Invalid email or password")
    token, expires = create_access_token(str(user["_id"]), user["role"])
    return TokenOut(access_token=token, expires_in=expires, user=public_user(user))

@router.get("/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return public_user(user)
