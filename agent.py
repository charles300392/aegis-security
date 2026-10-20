
import json

from dotenv import load_dotenv
from litellm import completion

from aegis import execute_tool, inspect_tool_result
from approval_ui import request_human_approval
from risk_engine import assess_risk


load_dotenv()

MODEL = "deepseek/deepseek-flash"
MAX_TOOL_ROUNDS = 8


tools = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a permitted text file from the project workspace."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                },
                "required": ["filename"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the local synthetic document index. "
                "This tool does not access the public internet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_customer",
            "description": (
                "Look up one fictional customer using an ID such as "
                "CUST-1001. Only synthetic demo records are available."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string"},
                },
                "required": ["customer_id"],
                "additionalProperties": False,
            },
        },
    },
]


def run_agent(user_input):
    """Run one conversation turn with AEGIS-mediated tool execution."""

    messages = [
        {
            "role": "user",
            "content": user_input,
        }
    ]

    for _ in range(MAX_TOOL_ROUNDS):
        response = completion(
            model=MODEL,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )

        message = response.choices[0].message

        messages.append(
            message.model_dump(exclude_none=True)
        )

        if not message.tool_calls:
            return message.content or ""

        for tool_call in message.tool_calls:
            tool_name = tool_call.function.name

            try:
                arguments = json.loads(
                    tool_call.function.arguments
                )
            except (json.JSONDecodeError, TypeError):
                arguments = None

            print(f"\n[Tool requested] {tool_name}")

            # A preliminary risk assessment is used only to decide whether
            # to display the approval UI. It does not authorize execution;
            # execute_tool always performs the mandatory checks itself.
            preliminary_assessment = assess_risk(tool_name, arguments)

            if preliminary_assessment.get("decision") == "VALIDATE":
                result = execute_tool(
                    tool_name,
                    arguments,
                    approval_callback=request_human_approval,
                )
            else:
                # Keep the existing two-argument call for ALLOW/BLOCK paths
                # and compatibility with integrations that wrap execute_tool.
                result = execute_tool(tool_name, arguments)

            safe_result = inspect_tool_result(
                tool_name,
                result,
            )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": safe_result,
                }
            )

    return (
        "The agent reached its maximum tool-call rounds. "
        "Please try a more specific request."
    )


if __name__ == "__main__":
    print("================================")
    print("       AEGIS SECURITY AGENT     ")
    print("================================")
    print("Available tools: read_file, web_search, lookup_customer")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input("You: ").strip()

            if user_input.lower() == "exit":
                break

            if not user_input:
                continue

            answer = run_agent(user_input)

            print("\nAgent:")
            print(answer)
            print()

        except KeyboardInterrupt:
            print("\nAgent interrupted.")
            break
        except Exception:
            print(
                "\n[AEGIS] The request failed. "
                "Check the application configuration and logs."
            )
