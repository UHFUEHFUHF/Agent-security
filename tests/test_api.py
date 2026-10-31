import os
os.environ["DATABASE_URL"] = "sqlite:///./test_agentshield.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production-123456789"
os.environ["GROQ_API_KEY"] = ""
os.environ["BOOTSTRAP_ADMIN"] = "true"

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import Base, engine

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
client = TestClient(app)

def register(email, password="Strong-test-password-123"):
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})

def token_for(email, password="Strong-test-password-123"):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]

def test_health():
    assert client.get("/health").status_code == 200

def test_register_login_me():
    assert register("admin@example.com").status_code == 201
    token = token_for("admin@example.com")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"

def test_weak_password_rejected():
    assert client.post("/api/v1/auth/register", json={"email": "weak@example.com", "password": "weak"}).status_code == 422

def test_scenario_and_metrics():
    token = token_for("admin@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/scenarios/run", headers=headers, json={
        "task": "Read invoice and prepare payment", "scenario_type": "mixed", "use_llm": False})
    assert response.status_code == 200, response.text
    assert response.json()["attack_blocked"] is True
    assert any(a["decision"] == "blocked" for a in response.json()["actions"])
    assert client.get("/api/v1/metrics?scope=all", headers=headers).status_code == 200

def test_auth_required():
    assert client.post("/api/v1/scenarios/run", json={"scenario_type": "malicious"}).status_code == 401

def test_user_cannot_read_other_users_run():
    admin_token = token_for("admin@example.com")
    run = client.post("/api/v1/scenarios/run", headers={"Authorization": f"Bearer {admin_token}"},
                      json={"task": "invoice", "scenario_type": "legitimate", "use_llm": False}).json()
    assert register("user@example.com").status_code == 201
    user_token = token_for("user@example.com")
    response = client.get(f"/api/v1/runs/{run['id']}", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 403

def test_admin_route_forbidden_for_user():
    register("regular@example.com")
    token = token_for("regular@example.com")
    assert client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403
