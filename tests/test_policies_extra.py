from app.security.policies import authorize_action

def test_email_body_must_be_string():
    assert not authorize_action("send_email", {"recipient": "owner-demo@example.test", "body": ["not", "text"]})[0]

def test_payment_bool_is_rejected():
    assert not authorize_action("prepare_payment", {"vendor": "demo-vendor", "amount": True})[0]

def test_browser_query_is_bounded():
    assert not authorize_action("browser_search", {"query": "x" * 301})[0]
