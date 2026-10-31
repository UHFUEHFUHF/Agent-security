# AgentShield Step 4 upgrade overlay

This overlay adds the next implementation layer to an existing `agentshield-backend` project:

- deterministic semantic/task-alignment Guardian in front of the existing tool allow-list;
- synthetic Red Team artifact is included as untrusted context for the target;
- unique trace IDs for runs and individual actions;
- deterministic judge for protected reads, canary markers, email and payment side effects;
- separate training and held-out case families;
- training-only feedback records (held-out cases are never passed to the updater);
- per-round scoreboard metrics and run replay endpoint.

## Install

Back up your project before overlaying. From the folder containing `agentshield-backend`:

```bash
cp -a agentshield-backend agentshield-backend-before-step4
unzip -o ~/Downloads/agentshield-step4-overlay.zip
cp -a agentshield-step4-overlay/. agentshield-backend/
cd agentshield-backend
source .venv/bin/activate
pytest -q
```

If the ZIP was downloaded to another location, change the ZIP path accordingly. The archive extracts into `agentshield-step4-overlay/`; the `cp` command overlays those files onto your project.

## Run

```bash
uvicorn app.main:app --reload
```

Use `/docs`, log in to obtain a JWT, then call `POST /api/v1/arena/run` with:

```json
{"rounds": 3, "attacks_per_round": 4, "include_heldout": true}
```

Then inspect `GET /api/v1/arena/history` and `GET /api/v1/arena/replay/{run_id}`.

## Important scope and safety notes

- All tools remain synthetic/in-memory. No real email, payment, or external browser actions are performed.
- The feedback updater records training-only evidence; it deliberately does not rewrite or weaken policies automatically. This avoids unsafe self-modification and held-out leakage.
- Metrics are an initial benchmark, not proof of security. A true autonomous co-evolution loop still needs repeated attack mutation, frozen benchmark versioning, a larger benign suite, regression rollback, and human-reviewed policy updates.
- Keep `.env` out of ZIPs and Git. Do not put API keys in source files.
