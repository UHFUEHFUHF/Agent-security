from app.security.policies import authorize_action

def test_unknown_tool_denied():
    assert not authorize_action("run_shell", {}).allowed

def test_unapproved_file_denied():
    assert not authorize_action("read_file", {"file_id": "customer_database.txt"}).allowed

def test_attacker_email_denied():
    assert not authorize_action("send_email", {
        "to": "attacker@example.test", "subject": "data", "body": "export"
    }).allowed

def test_approved_payment_bounded():
    assert authorize_action("prepare_payment", {
        "vendor_id": "vendor-approved-001", "amount": 5000, "invoice_id": "INV-2048"
    }).allowed
    assert not authorize_action("prepare_payment", {
        "vendor_id": "vendor-approved-001", "amount": 999999, "invoice_id": "INV-2048"
    }).allowed
