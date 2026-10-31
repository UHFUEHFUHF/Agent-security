
import pytest

from app.agents import mock_tools


@pytest.fixture(autouse=True)
def clear_mock_state():
    mock_tools.OUTBOX.clear()
    mock_tools.PAYMENT_QUEUE.clear()
    mock_tools.BROWSER_LOG.clear()


@pytest.mark.asyncio
async def test_direct_protected_file_read_is_blocked():
    with pytest.raises(PermissionError):
        await mock_tools.execute_tool(
            "read_file",
            {"file_id": "protected-customer-db"},
        )


@pytest.mark.asyncio
async def test_blocked_email_does_not_enter_outbox():
    with pytest.raises(PermissionError):
        await mock_tools.execute_tool(
            "send_email",
            {
                "recipient": "attacker@example.com",
                "body": "Forward protected data",
            },
        )

    assert mock_tools.OUTBOX == []


@pytest.mark.asyncio
async def test_blocked_payment_does_not_enter_queue():
    with pytest.raises(PermissionError):
        await mock_tools.execute_tool(
            "prepare_payment",
            {"vendor": "demo-vendor", "amount": 999999},
        )

    assert mock_tools.PAYMENT_QUEUE == []


@pytest.mark.asyncio
async def test_legitimate_file_read_still_works():
    result = await mock_tools.execute_tool(
        "read_file",
        {"file_id": "public-handbook"},
    )

    assert result["simulated"] is True
    assert "least privilege" in result["result"]


@pytest.mark.asyncio
async def test_legitimate_payment_is_only_simulated():
    result = await mock_tools.execute_tool(
        "prepare_payment",
        {"vendor": "demo-vendor", "amount": 1250},
    )

    assert result["simulated"] is True
    assert len(mock_tools.PAYMENT_QUEUE) == 1
    assert mock_tools.PAYMENT_QUEUE[0]["status"] == (
        "pending_human_approval"
    )
