from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

client = None
database = None

async def connect_to_mongo():
    global client, database
    client = AsyncIOMotorClient(
        settings.mongodb_uri,
        serverSelectionTimeoutMS=5000,
        uuidRepresentation="standard",
    )
    await client.admin.command("ping")
    database = client[settings.mongodb_database]
    from app.db.migrations import run_migrations
    await run_migrations(database)

async def close_mongo():
    global client, database
    if client is not None:
        client.close()
    client = database = None

def get_db():
    if database is None:
        raise RuntimeError("Database is not connected")
    return database
