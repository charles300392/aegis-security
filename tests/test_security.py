import json
import os

from aegis import (
    authorize_tool,
    LOG_FILE
)


def test_allowed_file():
    result = authorize_tool(
        "read_file",
        {"filename": "notes.txt"}
    )

    assert result is True


def test_env_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": ".env"}
    )

    assert result is False


def test_parent_directory_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "../.env"}
    )

    assert result is False


def test_double_parent_directory_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "../../.env"}
    )

    assert result is False


def test_python_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "../aegis.py"}
    )

    assert result is False


def test_unknown_tool_blocked():
    result = authorize_tool(
        "delete_file",
        {"filename": "notes.txt"}
    )

    assert result is False


def test_pem_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "private.pem"}
    )

    assert result is False


def test_key_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "private.key"}
    )

    assert result is False


def test_p12_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "certificate.p12"}
    )

    assert result is False


def test_pfx_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "certificate.pfx"}
    )

    assert result is False


def test_ssh_private_key_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "id_rsa"}
    )

    assert result is False


def test_ed25519_private_key_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "id_ed25519"}
    )

    assert result is False


def test_missing_filename_blocked():
    result = authorize_tool(
        "read_file",
        {}
    )

    assert result is False


def test_nonexistent_file_blocked():
    result = authorize_tool(
        "read_file",
        {"filename": "does_not_exist.txt"}
    )

    assert result is False


def test_allowed_file_logged():
    authorize_tool(
        "read_file",
        {"filename": "notes.txt"}
    )

    assert os.path.exists(LOG_FILE)

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        lines = log_file.readlines()

    event = json.loads(lines[-1])

    assert event["tool"] == "read_file"
    assert event["target"] == "notes.txt"
    assert event["decision"] == "ALLOW"
    assert event["reason"] == "Valid workspace file"


def test_blocked_file_logged():
    authorize_tool(
        "read_file",
        {"filename": ".env"}
    )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        lines = log_file.readlines()

    event = json.loads(lines[-1])

    assert event["tool"] == "read_file"
    assert event["target"] == ".env"
    assert event["decision"] == "BLOCK"
    assert event["reason"] == "Sensitive file"


def test_unknown_tool_logged():
    authorize_tool(
        "delete_file",
        {"filename": "notes.txt"}
    )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        lines = log_file.readlines()

    event = json.loads(lines[-1])

    assert event["tool"] == "delete_file"
    assert event["decision"] == "BLOCK"
    assert event["reason"] == "Unknown or unauthorized tool"


def test_log_contains_timestamp():
    authorize_tool(
        "read_file",
        {"filename": "notes.txt"}
    )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        lines = log_file.readlines()

    event = json.loads(lines[-1])

    assert "timestamp" in event
    assert event["timestamp"]