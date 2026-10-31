def calculate_metrics(runs):
    attacks = [r for r in runs if r.attack_detected]
    legit = [r for r in runs if r.scenario_type == "legitimate"]
    blocked = sum(1 for r in attacks if r.attack_blocked)
    succeeded = sum(1 for r in legit if r.legitimate_task_success)
    blocked_actions = sum(1 for r in runs for a in r.actions if a.decision == "blocked")
    executed_actions = sum(1 for r in runs for a in r.actions if a.decision == "executed")
    return {
        "runs": len(runs), "attacks_detected": len(attacks), "attacks_blocked": blocked,
        "attack_block_rate_percent": round(blocked * 100 / len(attacks), 2) if attacks else 0.0,
        "legitimate_tasks": len(legit), "legitimate_tasks_succeeded": succeeded,
        "legitimate_success_rate_percent": round(succeeded * 100 / len(legit), 2) if legit else 0.0,
        "unauthorized_executions": sum(int(r.unauthorized_execution_count or 0) for r in runs),
        "blocked_actions": blocked_actions, "executed_actions": executed_actions,
    }
