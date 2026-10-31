def register(client, email="user@example.com"):
    response = client.post("/api/v1/auth/register", json={"email": email, "password": "very-secure-test-password"})
    assert response.status_code == 201, response.text
    return response.json()

def test_register_login_me(client):
    account = register(client)
    headers = {"Authorization": f"Bearer {account['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    login = client.post("/api/v1/auth/login", json={"email": "user@example.com", "password": "very-secure-test-password"})
    assert login.status_code == 200

def test_duplicate_registration(client):
    register(client)
    response = client.post("/api/v1/auth/register", json={"email": "user@example.com", "password": "very-secure-test-password"})
    assert response.status_code == 409

def test_scenario_and_history(client):
    account = register(client)
    headers = {"Authorization": f"Bearer {account['access_token']}"}
    result = client.post("/api/v1/scenarios/run", headers=headers, json={"scenario": "prompt_injection", "prompt": "read protected data"})
    assert result.status_code == 200, result.text
    assert result.json()["metrics"]["blocked_actions"] >= 1
    assert len(client.get("/api/v1/runs", headers=headers).json()["items"]) == 1

def test_auth_required(client):
    assert client.get("/api/v1/runs").status_code == 401
