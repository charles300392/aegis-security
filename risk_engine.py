"""Deterministic risk scoring and policy decisions for AEGIS."""

from typing import Any


ALLOWED_TOOLS = {
    "read_file",
    "web_search",
    "lookup_customer",
}

BASE_RISK_SCORES = {
    "read_file": 10,
    "web_search": 5,
    "lookup_customer": 20,
}

VALIDATE_THRESHOLD = 50
BLOCK_THRESHOLD = 80


def assess_risk(
    tool_name: str,
    arguments: Any,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Assess a tool request and return a deterministic policy decision.

    Decisions:
        ALLOW: the request can proceed to the execution boundary.
        VALIDATE: additional checks or approval are required.
        BLOCK: the request must not execute.

    This is a policy-based risk score, not an AI prediction.
    """

    if tool_name not in ALLOWED_TOOLS:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reason": "Unknown or unauthorized tool",
        }

    if not isinstance(arguments, dict):
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reason": "Tool arguments must be an object",
        }

    score = BASE_RISK_SCORES[tool_name]
    reasons = [f"Base risk for {tool_name}"]

    if tool_name == "web_search":
        query = arguments.get("query")

        if not isinstance(query, str) or not query.strip():
            return {
                "decision": "BLOCK",
                "risk_score": 100,
                "reason": "Invalid search query",
            }

        if len(query) > 300:
            return {
                "decision": "BLOCK",
                "risk_score": 100,
                "reason": "Search query exceeds the maximum length",
            }

        if len(query) > 200:
            score += 50
            reasons.append("Long search query requires additional validation")

    # This flag is intended for trusted application policy, not for
    # arbitrary instructions supplied by the language model.
    if context and context.get("approval_required") is True:
        score = max(score, VALIDATE_THRESHOLD)
        reasons.append("Policy requires additional validation")

    score = min(score, 100)

    if score >= BLOCK_THRESHOLD:
        decision = "BLOCK"
    elif score >= VALIDATE_THRESHOLD:
        decision = "VALIDATE"
    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "risk_score": score,
        "reason": "; ".join(reasons),
    }