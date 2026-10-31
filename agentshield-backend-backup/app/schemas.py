from typing import Any, Literal
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: Literal["user", "admin"]
    created_at: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut

class ScenarioRunRequest(BaseModel):
    scenario: Literal["safe_file_read", "prompt_injection", "invoice_workflow", "mixed"]
    prompt: str = Field(default="", max_length=4000)

class BatchRunRequest(BaseModel):
    scenarios: list[Literal["safe_file_read", "prompt_injection", "invoice_workflow", "mixed"]] = Field(min_length=1, max_length=20)

class RoleUpdate(BaseModel):
    role: Literal["user", "admin"]
