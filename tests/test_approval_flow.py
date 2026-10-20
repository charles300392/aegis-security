import json

import aegis


def test_validate_request_is_executed_after_explicit_approval(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")
    executed = []

    def fake_web_search(query):
        executed.append(query)
        return "synthetic result"

    monkeypatch.setitem(aegis.TOOL_HANDLERS, "web_search", fake_web_search)

    def approve(tool_name, arguments, assessment):
        assert tool_name == "web_search"
        assert arguments == {"query": "a" * 201}
        assert assessment["decision"] == "VALIDATE"
        return True

    result = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
        approval_callback=approve,
    )

    assert result == "synthetic result"
    assert executed == ["a" * 201]
    events = [
        json.loads(line)
        for line in (tmp_path / "aegis.log").read_text(encoding="utf-8").splitlines()
    ]
    assert any(event["decision"] == "APPROVE" for event in events)
    assert any(event["decision"] == "EXECUTE" for event in events)


def test_validate_request_is_not_executed_when_human_denies(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")
    executed = []
    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        lambda query: executed.append(query) or "should not execute",
    )

    result = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
        approval_callback=lambda *_: False,
    )

    assert result == "AEGIS approval denied this tool call."
    assert executed == []


def test_validate_request_fails_closed_when_approval_ui_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")
    executed = []
    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        lambda query: executed.append(query) or "should not execute",
    )

    def broken_approval(*_):
        raise RuntimeError("dialog unavailable")

    result = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
        approval_callback=broken_approval,
    )

    assert result == "AEGIS approval denied this tool call."
    assert executed == []


def test_approval_is_rejected_if_risk_assessment_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "LOG_FILE", tmp_path / "aegis.log")
    executed = []
    monkeypatch.setitem(
        aegis.TOOL_HANDLERS,
        "web_search",
        lambda query: executed.append(query) or "should not execute",
    )

    original_assess = aegis.assess_risk
    calls = 0

    def changing_assessment(tool_name, arguments, context=None):
        nonlocal calls
        calls += 1
        result = original_assess(tool_name, arguments, context)
        if calls > 1:
            result = {**result, "risk_score": result["risk_score"] + 1}
        return result

    monkeypatch.setattr(aegis, "assess_risk", changing_assessment)

    result = aegis.execute_tool(
        "web_search",
        {"query": "a" * 201},
        approval_callback=lambda *_: True,
    )

    assert result == "AEGIS blocked this tool call."
    assert executed == []
