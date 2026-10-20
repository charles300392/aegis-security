# AEGIS Security

**A security gateway for AI agents**

AEGIS Security is a Python-based security gateway designed to control tool execution by AI agents. It evaluates tool requests, applies risk-based security policies, requests human approval when required, and records security events for auditing.

## Key Features

- **Tool authorization:** evaluates tool requests before execution.
- **Risk-based decisions:** supports `ALLOW`, `VALIDATE`, and `BLOCK` decisions.
- **Human approval:** provides a confirmation interface for requests requiring validation.
- **Input and path validation:** restricts unauthorized file access and unsafe paths.
- **Untrusted tool output handling:** marks tool results as untrusted data before returning them to the agent.
- **Audit logging:** records security-relevant events.
- **Automated testing and benchmarking:** evaluates policy decisions against defined scenarios.

## Architecture

```text
User
 |
 v
AI Agent
 |
 v
AEGIS Security Gateway
 |
 +--> Input and argument validation
 |
 +--> Risk assessment
 |
 +--> Security policy decision
 |       |
 |       +--> ALLOW
 |       +--> VALIDATE --> Human approval
 |       +--> BLOCK
 |
 v
Authorized Tool Execution
 |
 v
Untrusted Result Handling
 |
 v
AI Agent
```

## Requirements

- Python 3.11 or compatible version
- Dependencies listed in `requirements.txt`
- A configured LLM provider if using model-powered agent functionality

## Installation

Clone the repository and open its directory:

```bash
git clone <>
cd aegis-security
```

Create and activate a virtual environment on Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Configure the environment variables required by your chosen LLM provider before launching the model-powered agent. Never commit API keys or other secrets.

## Running AEGIS

Run the agent:

```bash
python agent.py
```

Run the deterministic security benchmark:

```bash
python -m benchmark.runner
```

Run the automated test suite:

```bash
python -m pytest -q
```

Benchmark output is saved under `benchmark/results/`.

## Current Validation Results

The current local test run completed successfully:

- Automated tests: **86 passed**
- Deterministic benchmark scenarios: **10**
- Decision accuracy on the tested scenarios: **100%**
- Attack block rate on the tested scenarios: **100%**
- Unsafe allow rate on the tested scenarios: **0%**
- Legitimate false-positive rate on the tested scenarios: **0%**

These results apply only to the implemented test cases. They do not establish protection against every possible prompt injection or tool-abuse attack.

## Security Scope and Limitations

AEGIS is a security enforcement layer between an AI agent and its tools. It is intended to reduce risks such as unauthorized file access, unsafe tool calls, invalid arguments, and malicious instructions embedded in tool outputs.

The current benchmark uses defined scenarios and simulated tool handlers. Results should not be interpreted as a guarantee of production security. Broader adversarial testing, independent review, and deployment-specific hardening are still necessary.

## Project Structure

```text
aegis-security/
├── agent.py
├── aegis.py
├── approval_ui.py
├── risk_engine.py
├── tools.py
├── benchmark/
│   ├── runner.py
│   ├── scenarios.py
│   └── results/
├── tests/
├── workspace/
├── requirements.txt
└── README.md
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
