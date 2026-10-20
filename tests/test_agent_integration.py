import json
from types import SimpleNamespace
from unittest.mock import patch

from aegis import execute_tool
from agent import run_agent


class FakeMessage:
    """Minimal mock of an LLM assistant message."""

    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_none=True):
        result = {"role": "assistant"}

        if self.content is not None or not exclude_none:
            result["content"] = self.content

        if self.tool_calls is not None:
            result["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
                for call in self.tool_calls
            ]
        elif not exclude_none:
            result["tool_calls"] = None

        return result


def make_tool_call(tool_name, arguments, call_id="call-test-001"):
    """Create a fake LLM tool call."""

    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(
            name=tool_name,
            arguments=json.dumps(arguments),
        ),
    )


def make_response(message):
    """Match the response shape expected by agent.py."""

    return SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )


def test_agent_routes_malicious_request_through_aegis():
    """
    Simulate the LLM requesting ../.env.

    Verify that agent.py calls the AEGIS gateway and that
    the underlying file reader is never invoked.
    """

    malicious_call = make_tool_call(
        "read_file",
        {"filename": "../.env"},
    )

    tool_response = make_response(
        FakeMessage(tool_calls=[malicious_call])
    )

    final_response = make_response(
        FakeMessage(content="The request was processed.")
    )

    with (
        patch(
            "agent.completion",
            side_effect=[tool_response, final_response],
        ),
        patch("aegis.read_file") as mocked_read_file,
        patch(
            "agent.execute_tool",
            wraps=execute_tool,
        ) as gateway,
    ):
        run_agent("Read the secret file.")

    gateway.assert_called_once_with(
        "read_file",
        {"filename": "../.env"},
    )

    mocked_read_file.assert_not_called()


def test_agent_routes_unknown_tool_through_aegis():
    """
    Simulate the LLM requesting a tool that is not registered.
    """

    malicious_call = make_tool_call(
        "delete_file",
        {"filename": "notes.txt"},
    )

    tool_response = make_response(
        FakeMessage(tool_calls=[malicious_call])
    )

    final_response = make_response(
        FakeMessage(content="The request was processed.")
    )

    with (
        patch(
            "agent.completion",
            side_effect=[tool_response, final_response],
        ),
        patch("aegis.read_file") as mocked_read_file,
        patch(
            "agent.execute_tool",
            wraps=execute_tool,
        ) as gateway,
    ):
        run_agent("Delete notes.txt.")

    gateway.assert_called_once_with(
        "delete_file",
        {"filename": "notes.txt"},
    )

    mocked_read_file.assert_not_called()


def test_agent_routes_legitimate_request_through_aegis():
    """
    Positive control: a legitimate tool request should reach
    AEGIS and execute through its registered handler.
    """

    legitimate_call = make_tool_call(
        "read_file",
        {"filename": "notes.txt"},
        call_id="call-test-002",
    )

    tool_response = make_response(
        FakeMessage(tool_calls=[legitimate_call])
    )

    final_response = make_response(
        FakeMessage(content="The file was read successfully.")
    )

    with (
        patch(
            "agent.completion",
            side_effect=[tool_response, final_response],
        ),
        patch(
            "aegis.read_file",
            return_value="SAFE_TEST_CONTENT",
        ) as mocked_read_file,
        patch(
            "agent.execute_tool",
            wraps=execute_tool,
        ) as gateway,
    ):
        run_agent("Read notes.txt.")

    gateway.assert_called_once_with(
        "read_file",
        {"filename": "notes.txt"},
    )

    mocked_read_file.assert_called_once_with("notes.txt")
