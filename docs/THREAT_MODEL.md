# AEGIS Security — Threat Model

**Version:** 1.0  
**Status:** Initial project threat model

## 1. Purpose

AEGIS Security is a Python-based security gateway designed to control tool execution by AI agents. It evaluates tool requests, applies security policies, supports human approval for selected operations, and records security-relevant events.

This document defines the security objectives, assets, threat actors, attack scenarios, controls, assumptions, and limitations considered in the current project.

## 2. System Scope

The system includes:

- An AI agent that requests tool execution.
- The AEGIS gateway that evaluates tool requests.
- A risk engine that contributes to security decisions.
- A human approval interface for requests requiring validation.
- Tool handlers that perform the permitted operations.
- Audit logs that record security events.
- Tool-result handling that identifies returned content as untrusted data.

The current implementation uses synthetic tools and a local workspace for its demonstrations and tests.

## 3. Assets to Protect

| Asset                                     | Security objective                            |
| ----------------------------------------- | --------------------------------------------- |
| Environment variables and API credentials | Prevent unauthorized disclosure               |
| Files outside the authorized workspace    | Prevent unauthorized access                   |
| Tool execution privileges                 | Prevent unauthorized or unsafe operations     |
| Tool arguments                            | Reject invalid or prohibited inputs           |
| Tool results and agent context            | Reduce the risk of indirect prompt injection  |
| Audit logs                                | Preserve useful records of security decisions |
| Human approval decisions                  | Ensure validation is explicit and enforced    |

## 4. Threat Actors

### 4.1 Malicious User

A user may deliberately request unauthorized file access, invoke prohibited tools, or submit malformed arguments.

### 4.2 Indirect Prompt-Injection Attacker

An attacker may place malicious instructions in a file, search result, or other content that the agent retrieves. The content may attempt to override the user's original request or persuade the agent to invoke an unsafe tool.

### 4.3 Compromised or Misbehaving AI Agent

The model may select an inappropriate tool, generate unsafe arguments, or follow malicious instructions contained in retrieved content.

AEGIS must enforce its policies independently of whether the model behaves correctly.

## 5. Trust Boundaries

The primary trust boundaries are:

1. **User to agent:** user instructions enter the agent's context.
2. **Agent to gateway:** proposed tool calls cross into the enforcement layer.
3. **Gateway to tool handler:** only authorized requests should reach execution.
4. **Tool handler to agent:** returned content may contain untrusted instructions.
5. **Gateway to audit log:** security decisions are recorded for later review.
6. **Human approval to gateway:** approval must be associated with the operation being authorized.

## 6. Threat Scenarios

| ID   | Threat                                          | Expected security behavior                                        |
| ---- | ----------------------------------------------- | ----------------------------------------------------------------- |
| T-01 | Attempt to read an environment secrets file     | Block the request                                                 |
| T-02 | Path traversal outside the authorized workspace | Block the request                                                 |
| T-03 | Invocation of an unregistered tool              | Block the request                                                 |
| T-04 | Unexpected or invalid tool arguments            | Reject or block the request                                       |
| T-05 | Indirect prompt injection in a retrieved file   | Treat retrieved instructions as untrusted and enforce tool policy |
| T-06 | Indirect prompt injection in a search result    | Treat retrieved instructions as untrusted and enforce tool policy |
| T-07 | High-risk operation requiring human validation  | Request approval before execution                                 |
| T-08 | Human approval is denied                        | Do not execute the operation                                      |
| T-09 | Security-relevant tool activity occurs          | Record the decision in the audit log                              |
| T-10 | Tool returns malicious or misleading content    | Mark the result as untrusted before returning it to the agent     |

## 7. Security Controls

The current implementation includes the following controls:

- Tool authorization and argument validation.
- Risk-based `ALLOW`, `VALIDATE`, and `BLOCK` decisions.
- File-access restrictions and path validation.
- Human approval for selected validation-required operations.
- Fail-closed behavior when the approval interface encounters an error.
- Untrusted-data markers around tool results.
- JSONL audit logging.
- Automated tests for security decisions, execution boundaries, file access, and approval flows.

These controls reduce specific risks but do not eliminate all possible attack paths.

## 8. Assumptions

- The gateway is positioned on the execution path for tool calls.
- Tool handlers are accessed through the gateway in the intended deployment.
- The local workspace contains the files available to the agent.
- The current benchmark uses simulated handlers for dangerous operations.
- Human approval is available when a request requires validation.

If a tool can be invoked outside the gateway, the gateway cannot enforce its policy on that bypass path.

## 9. Out of Scope and Limitations

The current project does not establish complete protection against:

- Every possible prompt-injection technique.
- Compromise of the host operating system or Python runtime.
- Malicious code execution outside the gateway's control.
- All forms of data exfiltration.
- Compromise or tampering of audit logs by a sufficiently privileged attacker.
- Every possible race condition or vulnerability in tool handlers.
- Production-scale attacks not represented by the current test scenarios.

The current benchmark is limited to the scenarios implemented in the repository. Passing tests is evidence of expected behavior for those cases, not proof of universal security.

## 10. Validation Strategy

Security validation uses:

- Automated unit and integration tests.
- Malicious and legitimate tool-call scenarios.
- Deterministic benchmark metrics.
- Tests for file-access restrictions and path traversal.
- Tests for human approval and denial behavior.
- Audit-log inspection.

The current recorded validation includes 86 passing automated tests and a deterministic benchmark with 10 scenarios. The benchmark reports 100% decision accuracy, 100% attack blocking, 0% unsafe allows, and 0% legitimate false positives for those scenarios.

These results must be interpreted within the scope of the tested scenarios.

## 11. Future Work

Potential future improvements include:

- Expand the adversarial test dataset.
- Test additional indirect prompt-injection payloads.
- Verify that approval decisions cannot be reused for different requests.
- Strengthen audit-log integrity and monitoring.
- Add repeatable benchmark reporting and documented attack demonstrations.
- Conduct an independent security review before production deployment.

## 12. Conclusion

AEGIS Security introduces an enforcement layer between an AI agent and its tools. Its primary security objective is to evaluate tool requests independently of the model's intent, prevent selected unsafe operations, request human validation when required, and record security decisions.

The current implementation demonstrates these controls against a defined set of automated tests and benchmark scenarios. Further adversarial testing and deployment-specific review remain necessary.
