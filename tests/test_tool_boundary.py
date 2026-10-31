import pytest
from app.agents.mock_tools import OUTBOX, PAYMENT_QUEUE, execute_tool

@pytest.fixture(autouse=True)
def clear_mock_state():
    OUTBOX.clear()
    PAYMENT_QUEUE.clear()

@pytest.mark.asyncio
async def test_protected_file_read_is_blocked_at_tool_boundary():
    with pytest.raises(PermissionError):
        await execute_tool("read_file", {"file_id": "admin-secrets"})

@pytest.mark.asyncio
async def test_blocked_email_does_not_enter_outbox():
    with pytest.raises(PermissionError):
        await execute_tool("send_email", {"recipient": "attacker@example.com", "body": "Hello"})
    assert OUTBOX == []

@pytest.mark.asyncio
async def test_blocked_payment_does_not_enter_queue():
    with pytest.raises(PermissionError):
        await execute_tool("prepare_payment", {"vendor": "demo-vendor", "amount": 5001})
    assert PAYMENT_QUEUE == []

@pytest.mark.asyncio
async def test_legitimate_file_read_works():
    result = await execute_tool("read_file", {"file_id": "public-handbook"})
    assert result["simulated"] is True

@pytest.mark.asyncio
async def test_legitimate_payment_is_simulated():
    result = await execute_tool("prepare_payment", {"vendor": "demo-vendor", "amount": 1250})
    assert result["simulated"] is True
    assert PAYMENT_QUEUE[0]["status"] == "pending_human_approval"
