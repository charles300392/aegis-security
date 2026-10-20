"""Run the AEGIS security benchmark and calculate metrics."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import aegis
from benchmark.scenarios import SCENARIOS


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_PATH = (
    Path(__file__).resolve().parent / "results" / "latest.json"
)

POLICY_DECISIONS = {"ALLOW", "VALIDATE", "BLOCK"}


def _read_events(log_path: Path) -> list[dict]:
    """Read JSONL audit events from the benchmark log."""

    if not log_path.exists():
        return []

    events = []

    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return events


def _calculate_metrics(results: list[dict]) -> dict:
    """Calculate security metrics from observed scenario results."""

    malicious = [
        result for result in results
        if result["category"] == "malicious"
    ]

    legitimate = [
        result for result in results
        if result["category"] == "legitimate"
    ]

    total = len(results)

    blocked_attacks = sum(
        result["actual_decision"] == "BLOCK"
        for result in malicious
    )

    unsafe_allowed_attacks = sum(
        result["actual_decision"] == "ALLOW"
        for result in malicious
    )

    executed_attacks = sum(
        result["executed"]
        for result in malicious
    )

    legitimate_false_positives = sum(
        result["actual_decision"] in {"BLOCK", "VALIDATE"}
        for result in legitimate
    )

    validations = sum(
        result["actual_decision"] == "VALIDATE"
        for result in results
    )

    correct_decisions = sum(
        result["actual_decision"] == result["expected_decision"]
        for result in results
    )

    def percentage(numerator: int, denominator: int) -> float | None:
        if denominator == 0:
            return None
        return round(100 * numerator / denominator, 2)

    return {
        "scenario_count": total,
        "correct_decisions": correct_decisions,
        "decision_accuracy_percent": percentage(
            correct_decisions, total
        ),
        "malicious_scenario_count": len(malicious),
        "attack_block_rate_percent": percentage(
            blocked_attacks, len(malicious)
        ),
        "unsafe_allow_rate_percent": percentage(
            unsafe_allowed_attacks, len(malicious)
        ),
        "malicious_execution_rate_percent": percentage(
            executed_attacks, len(malicious)
        ),
        "legitimate_scenario_count": len(legitimate),
        "false_positive_rate_percent": percentage(
            legitimate_false_positives, len(legitimate)
        ),
        "validation_rate_percent": percentage(
            validations, total
        ),
        "blocked_attack_count": blocked_attacks,
        "unsafe_allowed_attack_count": unsafe_allowed_attacks,
        "executed_attack_count": executed_attacks,
        "legitimate_false_positive_count": legitimate_false_positives,
        "validation_count": validations,
    }


def run_benchmark(
    scenarios: list[dict] | None = None,
    output_path: str | Path | None = DEFAULT_REPORT_PATH,
    log_path: str | Path | None = None,
) -> dict:
    """
    Execute benchmark scenarios through the real AEGIS gateway.

    Tool handlers are replaced with safe stubs. Policy decisions,
    validation and gateway execution control remain real.

    Pass output_path=None to avoid writing a report.
    """

    selected_scenarios = (
        SCENARIOS if scenarios is None else scenarios
    )

    if log_path is None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="aegis-benchmark-"
        )
        log_file = Path(temporary_directory.name) / "aegis.log"
    else:
        temporary_directory = None
        log_file = Path(log_path)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")

    log_file.parent.mkdir(parents=True, exist_ok=True)

    results = []

    def simulated_read_file(filename: str) -> str:
        return f"SIMULATED FILE CONTENT: {filename}"

    def simulated_web_search(query: str) -> str:
        return f"SIMULATED SEARCH RESULT: {query}"

    def simulated_customer_lookup(customer_id: str) -> str:
        return f"SIMULATED CUSTOMER: {customer_id}"

    try:
        with (
            patch.object(aegis, "LOG_FILE", log_file),
            patch.object(aegis, "read_file", side_effect=simulated_read_file),
            patch.object(aegis, "web_search", side_effect=simulated_web_search),
            patch.object(
                aegis,
                "lookup_customer",
                side_effect=simulated_customer_lookup,
            ),
        ):
            for scenario in selected_scenarios:
                previous_event_count = len(_read_events(log_file))

                response = aegis.execute_tool(
                    scenario["tool"],
                    scenario["arguments"].copy(),
                )

                new_events = _read_events(log_file)[previous_event_count:]

                policy_events = [
                    event for event in new_events
                    if event.get("decision") in POLICY_DECISIONS
                ]

                actual_decision = (
                    policy_events[0]["decision"]
                    if policy_events
                    else "ERROR"
                )

                execution_events = [
                    event for event in new_events
                    if event.get("decision") == "EXECUTE"
                ]

                results.append({
                    "id": scenario["id"],
                    "category": scenario["category"],
                    "description": scenario["description"],
                    "tool": scenario["tool"],
                    "expected_decision": scenario["expected_decision"],
                    "actual_decision": actual_decision,
                    "decision_correct": (
                        actual_decision == scenario["expected_decision"]
                    ),
                    "executed": bool(execution_events),
                    "risk_score": (
                        policy_events[0].get("risk_score")
                        if policy_events else None
                    ),
                    "response": response,
                })

        report = {
            "benchmark": "AEGIS Security Benchmark",
            "version": 1,
            "note": (
                "Local deterministic scenarios using simulated tool handlers. "
                "Results describe only this benchmark, not all possible attacks."
            ),
            "metrics": _calculate_metrics(results),
            "results": results,
        }

        if output_path is not None:
            report_path = Path(output_path)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            report["report_path"] = str(report_path.resolve())

        return report

    finally:
        if temporary_directory is not None:
            temporary_directory.cleanup()


def main() -> None:
    """Run the benchmark and print a readable summary."""

    report = run_benchmark()
    metrics = report["metrics"]

    print("\n=== AEGIS Security Benchmark ===")
    print(f"Scenarios: {metrics['scenario_count']}")
    print(
        "Decision accuracy: "
        f"{metrics['decision_accuracy_percent']}%"
    )
    print(
        "Attack block rate: "
        f"{metrics['attack_block_rate_percent']}%"
    )
    print(
        "Unsafe allow rate: "
        f"{metrics['unsafe_allow_rate_percent']}%"
    )
    print(
        "Malicious execution rate: "
        f"{metrics['malicious_execution_rate_percent']}%"
    )
    print(
        "Legitimate false positive rate: "
        f"{metrics['false_positive_rate_percent']}%"
    )
    print(
        "Validation rate: "
        f"{metrics['validation_rate_percent']}%"
    )
    print(f"\nReport saved to: {report['report_path']}")

    failures = [
        result for result in report["results"]
        if not result["decision_correct"] or result["executed"]
        and result["category"] == "malicious"
    ]

    if failures:
        print("\nScenarios requiring investigation:")
        for result in failures:
            print(
                f"- {result['id']}: expected "
                f"{result['expected_decision']}, got "
                f"{result['actual_decision']}, "
                f"executed={result['executed']}"
            )


if __name__ == "__main__":
    main()