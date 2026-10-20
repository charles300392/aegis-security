from aegis import authorize_tool


def test_prompt_injection_attempt_to_env():
    """
    Simulate a compromised LLM attempting to access .env
    after being influenced by a malicious prompt injection.
    """

    malicious_tool_call = {
        "filename": "../.env"
    }

    result = authorize_tool(
        "read_file",
        malicious_tool_call
    )

    assert result is False


def test_prompt_injection_attempt_to_workspace_secret():
    """
    Simulate a compromised LLM attempting to access
    a sensitive file inside the workspace.
    """

    malicious_tool_call = {
        "filename": ".env"
    }

    result = authorize_tool(
        "read_file",
        malicious_tool_call
    )

    assert result is False


def test_prompt_injection_attempt_to_private_key():
    """
    Simulate a compromised LLM attempting to access
    a private key.
    """

    malicious_tool_call = {
        "filename": "id_rsa"
    }

    result = authorize_tool(
        "read_file",
        malicious_tool_call
    )

    assert result is False


def test_prompt_injection_attempt_to_project_file():
    """
    Simulate a compromised LLM attempting to escape
    the workspace and access a project file.
    """

    malicious_tool_call = {
        "filename": "../aegis.py"
    }

    result = authorize_tool(
        "read_file",
        malicious_tool_call
    )

    assert result is False