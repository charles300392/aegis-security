from unittest.mock import patch

from aegis import execute_tool


def test_compromised_model_cannot_read_env():
    """
    Simulate a compromised model requesting access to .env.

    Verify that AEGIS blocks the request before the underlying
    file-reading function is invoked.
    """

    malicious_tool_call = {
        "filename": "../.env",
    }

    # Observe the actual file-reading function without opening .env.
    with patch("aegis.read_file") as mocked_read_file:
        result = execute_tool(
            "read_file",
            malicious_tool_call,
        )

    assert result == "AEGIS blocked this tool call."

    # The critical security assertion:
    # the underlying tool must never have executed.
    mocked_read_file.assert_not_called()


def test_compromised_model_cannot_invoke_unknown_tool():
    """
    Simulate a compromised model requesting an unregistered tool.
    """

    with patch("aegis.read_file") as mocked_read_file:
        result = execute_tool(
            "delete_file",
            {"filename": "notes.txt"},
        )

    assert result == "AEGIS blocked this tool call."
    mocked_read_file.assert_not_called()


def test_authorized_request_reaches_tool():
    """
    Positive control: verify that the test can detect execution
    when a legitimate tool request is authorized.
    """

    with patch(
        "aegis.read_file",
        return_value="SAFE_TEST_CONTENT",
    ) as mocked_read_file:
        result = execute_tool(
            "read_file",
            {"filename": "notes.txt"},
        )

    assert result == "SAFE_TEST_CONTENT"
    mocked_read_file.assert_called_once_with("notes.txt")
