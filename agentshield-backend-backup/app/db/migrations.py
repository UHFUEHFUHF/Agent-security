from datetime import datetime, timezone

async def run_migrations(db):
    await db.schema_migrations.create_index("version", unique=True)
    applied = {d["version"] async for d in db.schema_migrations.find({}, {"version": 1})}
    migrations = [
        (1, "initial_indexes"),
        (2, "arena_round_indexes"),
    ]
    for version, name in migrations:
        if version in applied:
            continue
        await db.users.create_index("email", unique=True)
        await db.runs.create_index([("owner_id", 1), ("created_at", -1)])
        await db.runs.create_index("created_at")
        await db.action_logs.create_index([("run_id", 1), ("created_at", 1)])
        await db.audit_logs.create_index([("owner_id", 1), ("created_at", -1)])
        if version >= 2:
            await db.arena_rounds.create_index(
                [("owner_id", 1), ("created_at", -1)]
            )
            await db.arena_case_results.create_index(
                [("owner_id", 1), ("round", 1), ("case_id", 1)]
            )
            await db.arena_case_results.create_index(
                [("owner_id", 1), ("split", 1), ("created_at", -1)]
            )

        await db.schema_migrations.insert_one({
            "version": version, "name": name,
            "applied_at": datetime.now(timezone.utc),
        })
