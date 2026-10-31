from datetime import datetime, timedelta, timezone
import jwt
from app.core.config import settings

def create_access_token(user_id: str, role: str):
    seconds = settings.access_token_expire_minutes * 60
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": user_id, "role": role, "iat": now, "exp": now + timedelta(seconds=seconds), "type": "access"},
                       settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, seconds

def decode_access_token(token: str):
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
                      options={"require": ["sub", "iat", "exp"]})
