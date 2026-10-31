from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError
from app.db.mongo import get_db
from app.core.config import settings
from app.security.passwords import hash_password, verify_password
from app.security.tokens import create_access_token

router = APIRouter(prefix="/auth", tags=["authentication"])

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

@router.post("/register", status_code=201)
async def register(payload: RegisterRequest, db=Depends(get_db)):
    email = str(payload.email).lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    role = "admin" if settings.bootstrap_admin_email and email == settings.bootstrap_admin_email.lower() else "user"
    user = {
        "id": str(uuid4()),
        "email": email,
        "password_hash": hash_password(payload.password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
    }
    try:
        await db.users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Email already registered")
    return {"id": user["id"], "email": email, "role": role}

@router.post("/login")
async def login(payload: LoginRequest, db=Depends(get_db)):
    email = str(payload.email).lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user["id"], user.get("role", "user"))
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
        "user": {"id": user["id"], "email": user["email"], "role": user.get("role", "user")},
    }
