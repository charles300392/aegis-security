import json
import os
from pathlib import Path

import pytest

from aegis import execute_tool, LOG_FILE
from tools import read_file


def read_last_log_event():
    with open(LOG_FILE, "r", encoding="utf-8") as log_file:
        lines = log_file.readlines()

    return json.loads(lines[-1])


def test_execution_boundary_allows_permitted_file():
    result = execute_tool(
        "read_file",
        {"filename": "notes.txt"},
    )

    assert "AEGIS Security Project" in result


def test_execution_boundary_blocks_parent_traversal():
    result = execute_tool(
        "read_file",
        {"filename": "../aegis.py"},
    )

    assert result == "AEGIS blocked this tool call."

    event = read_last_log_event()
    assert event["decision"] == "BLOCK"


def test_execution_boundary_blocks_sensitive_file():
    result = execute_tool(
        "read_file",
        {"filename": ".env"},
    )

    assert result == "AEGIS blocked this tool call."

    event = read_last_log_event()
    assert event["decision"] == "BLOCK"
    assert event["reason"] == "Sensitive file"


def test_execution_boundary_blocks_unknown_tool():
    result = execute_tool(
        "delete_file",
        {"filename": "notes.txt"},
    )

    assert result == "AEGIS blocked this tool call."

    event = read_last_log_event()
    assert event["decision"] == "BLOCK"


def test_execution_boundary_blocks_invalid_arguments():
    result = execute_tool(
        "read_file",
        None,
    )

    assert result == "AEGIS blocked this tool call."

    event = read_last_log_event()
    assert event["decision"] == "BLOCK"
    assert event["reason"] == "Invalid tool arguments"


def test_file_tool_rejects_absolute_path():
    outside_file = Path(__file__).resolve().parents[1] / "aegis.py"

    with pytest.raises(PermissionError):
        read_file(str(outside_file))


def test_file_tool_rejects_parent_traversal():
    with pytest.raises(PermissionError):
        read_file("../aegis.py")


def test_file_tool_rejects_sensitive_extension():
    with pytest.raises(PermissionError):
        read_file("private.pem")


def test_file_tool_rejects_symlink_to_outside_workspace(tmp_path):
    workspace = Path(__file__).resolve().parents[1] / "workspace"

    outside_file = tmp_path / "external_test_file.txt"
    outside_file.write_text(
        "This file must not be accessible.",
        encoding="utf-8",
    )

    link_path = workspace / "test_external_link.txt"

    try:
        link_path.symlink_to(outside_file)

    except (OSError, NotImplementedError):
        pytest.skip(
            "Symbolic link creation is not permitted in this environment."
        )

    try:
        with pytest.raises(PermissionError):
            read_file(link_path.name)

    finally:
        if link_path.is_symlink():
            link_path.unlink()


def test_successful_execution_is_logged():
    execute_tool(
        "read_file",
        {"filename": "notes.txt"},
    )

    event = read_last_log_event()

    assert event["tool"] == "read_file"
    assert event["decision"] == "EXECUTE"
    assert event["reason"] == "Tool executed successfully"
    assert event["timestamp"]


def test_security_log_exists_after_execution():
    execute_tool(
        "read_file",
        {"filename": "notes.txt"},
    )

    assert os.path.isfile(LOG_FILE)
