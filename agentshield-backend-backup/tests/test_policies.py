from app.security.policies import authorize_action

def test_allowlisted_file():
    assert authorize_action("read_file", {"file_id": "public-handbook"})[0]

def test_protected_file_denied():
    assert not authorize_action("read_file", {"file_id": "protected-customer-db"})[0]

def test_bad_recipient_denied():
    assert not authorize_action("send_email", {"recipient": "attacker@example.com", "body": "x"})[0]

def test_payment_cap():
    assert not authorize_action("prepare_payment", {"vendor": "demo-vendor", "amount": 5001})[0]

def test_unknown_tool_denied():
    assert not authorize_action("drop_database", {})[0]
