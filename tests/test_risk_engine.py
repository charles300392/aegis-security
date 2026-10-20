import json

import aegis
from risk_engine import assess_risk


def test_normal_file_read_is_allowed():
    result = assess_risk(
        "read_file",
        {"filename": "notes.txt"},
    )

    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 10


def test_short_search_is_allowed():
    result = assess_risk(
        "web_search",
        {"query": "What is prompt injection?"},
    )

    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 5


def test_customer_lookup_is_allowed_by_risk_policy():
    result = assess_risk(
        "lookup_customer",
        {"customer_id": "CUST-1001"},
    )

    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 20


def test_long_search_requires_validation():
    result = assess_risk(
        "web_search",
        {"query": "a" * 201},
    )

    assert result["decision"] == "VALIDATE"
    assert result["risk_score"] == 55
    assert "validation" in result["reason"].lower()


def test_unknown_tool_is_blocked():
    result = assess_risk(
        "delete_file",
        {"filename": "notes.txt"},
    )

    assert result["decision"] == "BLOCK"
    assert result["risk_score"] == 100


def test_non_dictionary_arguments_are_blocked():
    result = assess_risk(
        "read_file",
        ["notes.txt"],
    )

    assert result["decision"] == "BLOCK"


def test_policy_can_require_additional_validation():
    result = assess_risk(
        "read_file",
        {"filename": "notes.txt"},
        context={"approval_required": True},
    )

    assert result["decision"] == "VALIDATE"
    assert result["risk_score"] >= 50


def test_gateway_does_not_execute_a_validate_request(
    tmp_path,
    monkeypatch,
):
    log_file = tmp_path / "aegis.log"
    monkeypatch.setattr(aegis, "LOG_FILE", log_file)

    executed = []

    def fake_web_search(query):
        executed.append(query)
        return "This result should not be returned."

    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        fake_web_search,
    )

    response = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
    )

    assert "requires additional validation" in response.lower()
    assert executed == []

    events = [
        json.loads(line)
        for line in log_file.read_text(encoding="utf-8").splitlines()
    ]

    assert any(event["decision"] == "VALIDATE" for event in events)
    assert not any(event["decision"] == "EXECUTE" for event in events)


def test_gateway_blocks_search_over_maximum_length(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")

    executed = []

    def fake_web_search(query):
        executed.append(query)
        return "Should not execute."

    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        fake_web_search,
    )

    response = aegis.execute_tool(
        "web_search",
        {"query": "a" * 301},
    )

    assert response == "AEGIS blocked this tool call."
    assert executed == []


def test_validate_request_never_calls_tool_handler(
    tmp_path,
    monkeypatch,
):
    """A VALIDATE decision must never execute the registered handler."""
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")

    execution_count = 0

    def fake_web_search(query):
        nonlocal execution_count
        execution_count += 1
        return "This should never be returned."

    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        fake_web_search,
    )

    response = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
    )

    assert "requires additional validation" in response.lower()
    assert execution_count == 0
