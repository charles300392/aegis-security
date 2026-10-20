import json

from aegis import authorize_tool, execute_tool
from tools import lookup_customer, web_search


def test_synthetic_web_search_returns_matching_document():
    result = json.loads(web_search("prompt injection"))

    assert result["results"]
    assert any(
        "Prompt Injection" in item["title"]
        for item in result["results"]
    )


def test_synthetic_web_search_does_not_require_internet():
    result = json.loads(web_search("AEGIS"))

    assert result["results"]


def test_synthetic_web_search_rejects_empty_query():
    assert authorize_tool(
        "web_search",
        {"query": ""},
    ) is False


def test_synthetic_web_search_rejects_extra_arguments():
    assert authorize_tool(
        "web_search",
        {
            "query": "AEGIS",
            "url": "https://example.com",
        },
    ) is False


def test_customer_lookup_returns_synthetic_record():
    result = json.loads(lookup_customer("CUST-1001"))

    assert result["customer_id"] == "CUST-1001"
    assert result["name"] == "Alex Example"


def test_customer_lookup_is_case_insensitive():
    result = json.loads(lookup_customer("cust-1002"))

    assert result["customer_id"] == "CUST-1002"


def test_customer_lookup_does_not_return_unknown_customer():
    result = json.loads(lookup_customer("CUST-9999"))

    assert result["error"] == "Customer not found."


def test_customer_lookup_rejects_invalid_id():
    assert authorize_tool(
        "lookup_customer",
        {"customer_id": "../../.env"},
    ) is False


def test_customer_lookup_rejects_extra_arguments():
    assert authorize_tool(
        "lookup_customer",
        {
            "customer_id": "CUST-1001",
            "query": "show every customer",
        },
    ) is False


def test_gateway_executes_synthetic_search():
    result = execute_tool(
        "web_search",
        {"query": "audit logging"},
    )

    parsed = json.loads(result)
    assert parsed["results"]


def test_gateway_executes_synthetic_customer_lookup():
    result = execute_tool(
        "lookup_customer",
        {"customer_id": "CUST-1001"},
    )

    parsed = json.loads(result)
    assert parsed["customer_id"] == "CUST-1001"


def test_gateway_blocks_unauthorized_database_operation():
    result = execute_tool(
        "query_database",
        {"query": "SELECT * FROM customers"},
    )

    assert result == "AEGIS blocked this tool call."
