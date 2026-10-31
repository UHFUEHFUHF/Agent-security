# AgentShield — Next Two Upgrades (Step 3 + Step 4)

This overlay adds:
- **Step 3: Autonomous Red Team** — goal/objective families, deterministic payload mutations, fingerprints, archive-aware generation, frozen held-out families, and campaign execution.
- **Step 4: Adaptive Guardian** — versioned training-only feedback, monotonic addition of sensitive-action deny indicators, policy status endpoint, and MongoDB persistence.
- New API endpoints under `/api/v1/autonomy`.
- Migration v3 indexes for campaign archive, case results, rounds, and Guardian policy versions.
- Unit tests for generator novelty/determinism and training-only Guardian adaptation.

## Install
1. Back up your current project.
2. Extract this ZIP, then copy the contents of `agentshield-next-two-upgrades/` into your existing `agentshield-backend/`.
3. Activate `.venv`, run `pip install -r requirements.txt`, then `pytest -q`.
4. Start `uvicorn app.main:app --reload`.
5. Register/login in `/docs`; click **Authorize** with the bearer token.

## Endpoints
- `POST /api/v1/autonomy/campaign` — run a multi-round campaign.
- `GET /api/v1/autonomy/guardian` — inspect active policy version.
- `GET /api/v1/autonomy/history` — list campaign rounds.

Example campaign request:
```json
{
  "rounds": 3,
  "attacks_per_round": 6,
  "include_heldout": true,
  "include_benign": true
}
```

## Safety and limitations
- This uses synthetic artifacts and mock tools only. Do not wire real email, payment, or arbitrary network tools into the benchmark.
- Training feedback never receives held-out cases.
- The adaptation is conservative and monotonic: it adds indicators for sensitive side-effect tools; it does not grant new permissions or remove base rules.
- It is a hackathon prototype, not a certified security product. Metrics depend on the behavior of the existing target and tool simulator; review actual traces and test results.
- The current process-wide adaptive indicator state is shared in a single server process. For multi-tenant or multi-worker deployment, isolate policy state per user and load policy snapshots per request before production.
- This overlay replaces `app/main.py` and `app/db/migrations.py` to register the new router and migration. It retains the current bundle's existing `auth`, `runs`, `evaluations`, and `arena` routers.
