from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.db.mongo import connect_to_mongo, close_mongo, get_db
from app.api import auth, runs, evaluations, arena

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    try:
        yield
    finally:
        await close_mongo()

app = FastAPI(title=settings.app_name, version="1.1.0", lifespan=lifespan)

@app.get("/health", tags=["health"])
async def health():
    try:
        await get_db().command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "degraded", "database": "unavailable"})

app.include_router(auth.router, prefix=settings.api_prefix)
app.include_router(runs.router, prefix=settings.api_prefix)
app.include_router(evaluations.router, prefix=settings.api_prefix)
app.include_router(arena.router, prefix=settings.api_prefix)
