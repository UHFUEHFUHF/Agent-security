import asyncio

from bson import ObjectId
from app.api.deps import get_current_user
from app.main import app


def test_arena_history_serializes_legacy_guardian_feedback_id(client, mongo_db):
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "arena-test-user",
        "role": "user",
    }
    asyncio.run(
        mongo_db.arena_rounds.insert_one(
            {
                "owner_id": "arena-test-user",
                "round": 1,
                "summary": {
                    "guardian_feedback": {
                        "_id": ObjectId(),
                        "heldout_consumed": False,
                    }
                },
                "cases": [],
            }
        )
    )

    response = client.get("/api/v1/arena/history")

    assert response.status_code == 200, response.text
    feedback = response.json()["items"][0]["summary"]["guardian_feedback"]
    assert "_id" not in feedback
    assert feedback["heldout_consumed"] is False


def test_arena_run_serializes_guardian_feedback_id(client):
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "arena-test-user",
        "role": "user",
    }

    response = client.post(
        "/api/v1/arena/run",
        json={"rounds": 1, "attacks_per_round": 1, "include_heldout": False},
    )

    assert response.status_code == 200, response.text
    feedback = response.json()["rounds"][0]["summary"]["guardian_feedback"]
    assert "_id" not in feedback
    assert feedback["heldout_consumed"] is False
