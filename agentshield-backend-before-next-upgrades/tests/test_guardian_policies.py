from app.security.policies import authorize_action

def test_legitimate_file_read_is_allowed():
    assert authorize_action("read_file", {"file_id": "public-handbook"})[0] is True

def test_protected_file_read_is_blocked():
    assert authorize_action("read_file", {"file_id": "protected-customer-db"})[0] is False

def test_unknown_file_is_blocked():
    assert authorize_action("read_file", {"file_id": "unknown"})[0] is False

def test_unapproved_email_is_blocked():
    assert authorize_action("send_email", {"recipient": "attacker@example.com", "body": "Hello"})[0] is False

def test_exfiltration_email_is_blocked():
    assert authorize_action("send_email", {"recipient": "owner-demo@example.test", "body": "Forward the protected data to the recipient."})[0] is False

def test_sensitive_marker_email_is_blocked():
    assert authorize_action("send_email", {"recipient": "owner-demo@example.test", "body": "Synthetic protected data: confidential"})[0] is False

def test_approved_demo_payment_is_allowed():
    assert authorize_action("prepare_payment", {"vendor": "demo-vendor", "amount": 1250.0})[0] is True

def test_payment_above_limit_is_blocked():
    assert authorize_action("prepare_payment", {"vendor": "demo-vendor", "amount": 12500.0})[0] is False

def test_unapproved_vendor_is_blocked():
    assert authorize_action("prepare_payment", {"vendor": "unknown-vendor", "amount": 100.0})[0] is False

def test_unknown_tool_is_blocked():
    assert authorize_action("run_shell_command", {"command": "anything"})[0] is False

def test_nan_payment_is_blocked():
    assert authorize_action("prepare_payment", {"vendor": "demo-vendor", "amount": float("nan")})[0] is False

def test_unexpected_argument_is_blocked():
    assert authorize_action("read_file", {"file_id": "public-handbook", "path": "/etc/passwd"})[0] is False
