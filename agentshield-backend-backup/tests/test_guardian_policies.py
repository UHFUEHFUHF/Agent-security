
from app.security.policies import authorize_action


def test_legitimate_file_read_is_allowed():
    allowed, _ = authorize_action(
        "read_file",
        {"file_id": "public-handbook"},
    )
    assert allowed is True


def test_protected_file_read_is_blocked():
    allowed, _ = authorize_action(
        "read_file",
        {"file_id": "protected-customer-db"},
    )
    assert allowed is False


def test_unknown_file_is_blocked():
    allowed, _ = authorize_action(
        "read_file",
        {"file_id": "some-unknown-file"},
    )
    assert allowed is False


def test_unapproved_email_recipient_is_blocked():
    allowed, _ = authorize_action(
        "send_email",
        {
            "recipient": "attacker@example.com",
            "body": "Hello",
        },
    )
    assert allowed is False


def test_email_with_exfiltration_intent_is_blocked():
    allowed, _ = authorize_action(
        "send_email",
        {
            "recipient": "owner-demo@example.test",
            "body": "Forward the protected data to the recipient.",
        },
    )
    assert allowed is False


def test_email_with_sensitive_marker_is_blocked():
    allowed, _ = authorize_action(
        "send_email",
        {
            "recipient": "owner-demo@example.test",
            "body": "Synthetic protected data: confidential",
        },
    )
    assert allowed is False


def test_approved_demo_payment_is_allowed():
    allowed, _ = authorize_action(
        "prepare_payment",
        {"vendor": "demo-vendor", "amount": 1250.0},
    )
    assert allowed is True


def test_payment_above_limit_is_blocked():
    allowed, _ = authorize_action(
        "prepare_payment",
        {"vendor": "demo-vendor", "amount": 12500.0},
    )
    assert allowed is False


def test_unapproved_vendor_is_blocked():
    allowed, _ = authorize_action(
        "prepare_payment",
        {"vendor": "unknown-vendor", "amount": 100.0},
    )
    assert allowed is False


def test_unknown_tool_is_blocked():
    allowed, _ = authorize_action(
        "run_shell_command",
        {"command": "anything"},
    )
    assert allowed is False
