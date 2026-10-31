# AgentShield Backend — MongoDB Atlas

FastAPI backend with JWT authentication, persistent MongoDB Atlas storage, role-based authorization, a deterministic guardian, optional Groq-powered agents, run history, metrics, audit logs, and versioned MongoDB migrations.

All tools use synthetic data. Emails and payments are simulated; no real external side effects occur.

## Setup (Ubuntu)

1. Create a MongoDB Atlas cluster and database user.
2. In Atlas Network Access, allow your current IP. Avoid `0.0.0.0/0` for normal use.
3. Choose **Connect → Drivers → Python** and copy the connection URI.
4. Configure your database user password; URL-encode special characters in it.
5. Install:

```bash
unzip agentshield-mongodb.zip
cd agentshield-mongodb
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`: set `MONGODB_URI`, `MONGODB_DATABASE`, and a strong `JWT_SECRET_KEY`. Generate a secret using `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Then run:

```bash
uvicorn app.main:app --reload
```

Docs: http://127.0.0.1:8000/docs | Health: http://127.0.0.1:8000/health

## Groq

Put your key in `GROQ_API_KEY` in `.env`. Leave it blank to use deterministic fallbacks. Never put the key in frontend code or commit `.env`.

## First admin bootstrap

Before first startup, set `BOOTSTRAP_ADMIN_EMAIL` to the exact email you will register. Register that account, then remove the variable and restart. This bootstrap is for a protected demo environment only.

## MongoDB migrations

MongoDB has no SQL-style migration system. `app/db/migrations.py` implements versioned, idempotent migrations and records applied versions in `schema_migrations`. Back up production data before deploying changes.

## Routes

- `POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`
- `POST /api/v1/scenarios/run`, `POST /api/v1/scenarios/batch`
- `GET /api/v1/runs`, `GET /api/v1/runs/{run_id}`
- `GET /api/v1/metrics`, `GET /api/v1/audit`
- `GET /api/v1/admin/users`, `PATCH /api/v1/admin/users/{user_id}/role` (admin only)

Scenarios: `safe_file_read`, `prompt_injection`, `invoice_workflow`, `mixed`.

## Tests

```bash
pytest -q
```

Tests use a mocked MongoDB-compatible database and do not require Atlas credentials. A real Atlas smoke test can be performed using Swagger UI.

## Production checklist

Use HTTPS, rotate secrets, restrict Atlas network access, apply least-privilege database access, enable backups, add rate limits/email verification, and review audit-data retention before public deployment.
