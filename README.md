# AgentShield — Complete Hackathon Backend

A FastAPI + MongoDB Atlas backend for the **Red Team vs Blue Team: Agents Attacking Agents** hackathon project. This bundle consolidates authentication, guarded mock tools, synthetic Red Team campaigns, conservative adaptive Guardian policy, round evaluation, benchmark metrics, trace replay, and scoreboard/history endpoints.

> **Safety boundary:** every tool is synthetic. `send_email` only writes to an in-memory mock outbox; `prepare_payment` only queues a simulated proposal; `browser_search` returns synthetic results. No real emails are sent, no money moves, and the browser tool does not make external requests. Do not replace these mocks with live integrations for the hackathon demo without a separate security review.

## Included functionality

- JWT authentication and role claim, password hashing, duplicate-email handling, authenticated APIs.
- MongoDB Atlas persistence, startup ping, versioned index migrations.
- Tool-boundary allow-list authorization, semantic task alignment, provenance and risk explanations.
- Synthetic target agent and Red Team payloads; autonomous template/mutation campaign generator with fingerprint archive.
- Round-based arena and autonomous campaign APIs.
- Conservative Guardian adaptation: only training-split cases are passed to learning; adaptation only adds deny/review indicators and never grants tool permissions.
- Frozen held-out case families excluded from Guardian learning.
- Judge metrics for protected reads, canary hits, unauthorized side effects, attack success and benign usefulness.
- Benchmark runs, per-user scoreboard/history, and read-only trace replay.
- Unit tests for policy boundary, semantic Guardian, adaptive policy, and attack generation.

## 1. Setup on Ubuntu

```bash
cd ~/Downloads/agentshield-cyber02
# Keep a rollback copy of the current project first:
cp -a agentshield-backend agentshield-backend-before-complete
unzip -o ~/Downloads/agentshield-complete.zip
cp -a agentshield-complete/. agentshield-backend/
cd agentshield-backend

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

If you already have a `.venv`, activate it instead of recreating it. **Do not overwrite your existing `.env`** if it already contains your secrets; merge the required variables manually.

## 2. Configure `.env`

Set these values locally; never commit `.env` or paste keys into source files.

```dotenv
APP_NAME=AgentShield API
ENVIRONMENT=development
API_PREFIX=/api/v1
JWT_SECRET_KEY=replace-with-a-long-random-secret-at-least-32-bytes
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>/<database>?retryWrites=true&w=majority
MONGODB_DATABASE=agentshield
GROQ_API_KEY=<your-groq-key>
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_TIMEOUT_SECONDS=20
BOOTSTRAP_ADMIN_EMAIL=<optional-admin-email>
```

- Create a MongoDB Atlas database user and allow your development IP in Atlas Network Access.
- URL-encode special characters in the MongoDB username/password.
- `BOOTSTRAP_ADMIN_EMAIL` only grants the admin role when that email registers; set it before registering the account.
- The app has deterministic fallback behavior when no Groq key is configured, depending on the agent implementation. Use your own key in `.env` for model-backed responses.

## 3. Run the test suite first

```bash
cd ~/Downloads/agentshield-cyber02/agentshield-backend
source .venv/bin/activate
PYTHONPATH=. python -m compileall -q app tests
PYTHONPATH=. python -m pytest -q
```

If tests fail, save the complete traceback. Do not treat a successful compile as proof of correct runtime integration. Some API integration tests require a reachable MongoDB instance or dependency configuration.

## 4. Start the API

```bash
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`. The database must be reachable for app startup because migrations run during startup.

## 5. Authentication flow

Register (password minimum 12 characters):

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"ChangeThisPassword123!"}'
```

Login and copy `access_token`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"ChangeThisPassword123!"}'
```

For authenticated endpoints, add `-H 'Authorization: Bearer YOUR_TOKEN'`.

## 6. Main endpoints

All API routes use `/api/v1` by default.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Database connectivity and synthetic-only status |
| POST | `/auth/register` | Register a user |
| POST | `/auth/login` | Get JWT |
| POST | `/runs` or GET `/runs` | Create/list scenario runs (see OpenAPI for request schema) |
| GET | `/runs/{run_id}` | Retrieve an owned run; admin can inspect any run |
| POST | `/evaluations/run` | Basic repeated scenario evaluation |
| POST | `/arena/run` | Round-based arena with held-out case |
| GET | `/arena/history` | Arena round history for current user |
| POST | `/autonomy/campaign` | Run autonomous synthetic Red Team + adaptive Guardian campaign |
| GET | `/autonomy/guardian` | Current persisted Guardian policy snapshot |
| GET | `/autonomy/history` | Autonomous campaign history |
| POST | `/benchmarks/run` | Run multi-round attack/benign/held-out benchmark |
| GET | `/benchmarks/scoreboard` | Per-user round summaries, newest first |
| GET | `/benchmarks/history` | Alias for scoreboard/history |
| GET | `/benchmarks/replay/{run_id}` | Read-only action timeline for an existing run |

### Autonomous campaign request

```json
{"rounds":3,"attacks_per_round":6,"include_heldout":true,"include_benign":true}
```

### Full benchmark request

```json
{"rounds":3,"attacks_per_round":6,"include_heldout":true,"include_benign":true}
```

The campaign/benchmark returns round summaries and case-level verdicts. Use a modest round count first while testing API quotas and latency.

## 7. Demo sequence

1. Register and log in; save the bearer token.
2. Call `/api/v1/arena/run` with 3 rounds to demonstrate baseline scenarios.
3. Call `/api/v1/autonomy/campaign` with 3 rounds, 6 attacks per round, held-out and benign controls enabled.
4. Call `/api/v1/benchmarks/run` to persist comparative metrics.
5. Inspect `/api/v1/benchmarks/scoreboard` and replay one case using `/api/v1/benchmarks/replay/{run_id}`.
6. Show blocked-action reasons, policy version, provenance, and benign usefulness side by side.
7. Use `/docs` for the live API demo; keep secrets hidden.

## 8. Important interpretation limits

- Benchmark numbers are measured results from this prototype, not security certification or proof that every attack is blocked.
- The Red Team generator uses deterministic templates and mutations; it is autonomous campaign generation, not unrestricted autonomous exploit research.
- Guardian adaptation is conservative and indicator-based. It is not a trained semantic classifier. Validate false-positive rate and held-out performance before making claims.
- Held-out examples are designed to be excluded from learner inputs. Inspect code and stored records during review.
- The current mock tool side effects live in process memory, while traces and evaluations persist in MongoDB.
- The target LLM can propose malformed or unexpected actions; all proposed tool calls must remain behind Guardian and tool-boundary authorization.
- A passing unit suite is necessary but not sufficient. Test against your own MongoDB Atlas and Groq configuration before the hackathon.

## 9. Troubleshooting

- `ServerSelectionTimeoutError`: verify Atlas URI, IP access list, credentials, and network access.
- `401 Unauthorized`: log in again and send the full bearer token.
- `409 Email already registered`: log in instead of registering again.
- Model API errors: verify `GROQ_API_KEY`, model name, quotas, and outbound connectivity.
- Import errors: activate `.venv` and reinstall `requirements.txt`.
- If any tests fail, capture `PYTHONPATH=. python -m pytest -q` output and fix before demoing.
