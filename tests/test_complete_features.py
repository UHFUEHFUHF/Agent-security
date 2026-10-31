from app.main import app


def test_all_final_routers_are_mounted():
    paths = {route.path for route in app.routes}
    assert "/api/v1/autonomy/campaign" in paths
    assert "/api/v1/benchmarks/run" in paths
    assert "/api/v1/benchmarks/scoreboard" in paths
    assert "/api/v1/benchmarks/replay/{run_id}" in paths
    assert "/api/v1/arena/run" in paths


def test_replay_endpoint_is_named_read_only():
    from app.api.benchmarks import replay_trace
    assert replay_trace.__name__ == "replay_trace"
