# AgentShield Backend

FastAPI backend for a synthetic red-team vs blue-team agent security arena.

## Safety model
- All file, email, browser, and payment tools are simulated.
- No real emails are sent and no money moves.
- Protected files are blocked by the Guardian policy and again at tool execution.
- Groq is optional. Without `GROQ_API_KEY`, deterministic fallback plans are used.
- Never commit `.env`, database credentials, or JWT secrets.

## Setup (Ubuntu)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with MongoDB Atlas URI, a strong JWT_SECRET_KEY, and optional GROQ_API_KEY
uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000/docs`.

## Authentication
1. `POST /api/v1/auth/register` with an email and password of at least 12 characters.
2. `POST /api/v1/auth/login`.
3. Click Authorize in Swagger and enter the returned bearer token.

## Main endpoints
- `GET /health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/runs`
- `GET /api/v1/runs/{run_id}`
- `POST /api/v1/evaluations/run`
- `POST /api/v1/arena/run`
- `GET /api/v1/arena/history`

Arena request:
```json
{"rounds": 3, "attacks_per_round": 4, "include_heldout": true}
```

## Tests
```bash
python -m compileall -q app
PYTHONPATH=. python -m pytest -q
```
The current suite includes policy and tool-boundary tests. Full API tests need a test database or dependency overrides; do not run destructive tests against production data.

## Important limitations
This is a starter implementation, not a completed research-grade co-evolution engine. The current arena logs case outcomes but does not learn new policies automatically, provide a validated vulnerable-vs-guarded benchmark, or implement a full 30-task benign benchmark. Metrics should not be presented as independently validated benchmark results until those features and tests exist.
