from app.security.semantic_guardian import decide_action


def test_protected_file_always_denied():
    result = decide_action("read_file", {"file_id":"admin-secrets"}, task="read public handbook", scenario="safe_file_read")
    assert result["allowed"] is False


def test_email_requires_explicit_task_intent():
    result = decide_action("send_email", {"recipient":"owner-demo@example.test", "body":"Hello"}, task="summarize handbook", scenario="safe_file_read")
    assert result["allowed"] is False
    assert result["policy"] == "task_alignment"


def test_payment_outside_task_scope_denied():
    result = decide_action("prepare_payment", {"vendor":"demo-vendor", "amount":100}, task="read the handbook", scenario="safe_file_read")
    assert result["allowed"] is False


def test_payment_in_invoice_task_remains_simulated_gate():
    result = decide_action("prepare_payment", {"vendor":"demo-vendor", "amount":1250}, task="inspect invoice and prepare payment proposal", scenario="invoice_workflow")
    assert result["allowed"] is True
    assert result["policy"] == "allow_with_gate"
