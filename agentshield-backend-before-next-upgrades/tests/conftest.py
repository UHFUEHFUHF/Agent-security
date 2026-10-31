import os
os.environ["JWT_SECRET_KEY"] = "test-secret-key-long-enough-for-unit-tests-123456"
os.environ["MONGODB_URI"] = "mongodb://localhost:27017"
os.environ["MONGODB_DATABASE"] = "agentshield_test"
os.environ["GROQ_API_KEY"] = ""

import pytest
from mongomock_motor import AsyncMongoMockClient
from fastapi.testclient import TestClient
from app.main import app
from app.db.mongo import get_db

@pytest.fixture
def mongo_db():
    client = AsyncMongoMockClient()
    db = client["agentshield_test"]
    yield db
    client.close()

@pytest.fixture
def client(mongo_db, monkeypatch):
    # Prevent the app lifespan from opening a real MongoDB connection during tests.
    import app.main as main_module
    async def no_connect():
        return None
    async def no_close():
        return None
    monkeypatch.setattr(main_module, "connect_to_mongo", no_connect)
    monkeypatch.setattr(main_module, "close_mongo", no_close)
    async def override_get_db():
        return mongo_db
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
