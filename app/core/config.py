from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "AgentShield API"
    environment: str = "development"
    api_prefix: str = "/api/v1"
    jwt_secret_key: str = "development-only-change-this-secret-123456"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    database_url: str = "sqlite:///./agentshield.db"
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = "agentshield"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_timeout_seconds: int = 20
    max_batch_scenarios: int = 25
    bootstrap_admin_email: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings():
    return Settings()

settings = get_settings()
