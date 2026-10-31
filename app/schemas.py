from datetime import datetime
from typing import Literal, Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut

class RoleUpdate(BaseModel):
    role: Literal["user", "admin"]

class ScenarioRequest(BaseModel):
    task: str = Field(default="Read the supplier invoice and prepare the stated payment", min_length=3, max_length=2000)
    scenario_type: Literal["legitimate", "malicious", "mixed"] = "mixed"
    use_llm: bool = True

class BatchScenarioRequest(BaseModel):
    scenarios: list[ScenarioRequest] = Field(min_length=1, max_length=12)

class ActionOut(BaseModel):
    id: int
    tool_name: str
    arguments: dict[str, Any]
    decision: str
    reason: str
    result: dict[str, Any] | None
    created_at: datetime

class RunOut(BaseModel):
    id: int
    owner_id: int
    scenario_type: str
    task: str
    status: str
    used_llm: bool
    attack_detected: bool
    attack_blocked: bool
    legitimate_task_success: bool
    unauthorized_execution_count: int
    summary: str
    metrics: dict[str, Any]
    created_at: datetime
    actions: list[ActionOut] = []

class RoleUpdate(BaseModel):
    role: Literal["user", "admin"]
