"""Tests for the AEGIS benchmark and its metrics."""

from benchmark.runner import _calculate_metrics, run_benchmark
from benchmark.scenarios import SCENARIOS


def test_metrics_handle_empty_results():
    metrics = _calculate_metrics([])

    assert metrics["scenario_count"] == 0
    assert metrics["decision_accuracy_percent"] is None
    assert metrics["attack_block_rate_percent"] is None
    assert metrics["false_positive_rate_percent"] is None


def test_metrics_calculate_attack_block_rate():
    results = [
        {
            "category": "malicious",
            "actual_decision": "BLOCK",
            "expected_decision": "BLOCK",
            "executed": False,
        },
        {
            "category": "malicious",
            "actual_decision": "ALLOW",
            "expected_decision": "BLOCK",
            "executed": True,
        },
    ]

    metrics = _calculate_metrics(results)

    assert metrics["attack_block_rate_percent"] == 50.0
    assert metrics["unsafe_allow_rate_percent"] == 50.0
    assert metrics["malicious_execution_rate_percent"] == 50.0


def test_metrics_count_validation_as_a_legitimate_false_positive():
    results = [
        {
            "category": "legitimate",
            "actual_decision": "VALIDATE",
            "expected_decision": "ALLOW",
            "executed": False,
        },
        {
            "category": "legitimate",
            "actual_decision": "ALLOW",
            "expected_decision": "ALLOW",
            "executed": True,
        },
    ]

    metrics = _calculate_metrics(results)

    assert metrics["false_positive_rate_percent"] == 50.0
    assert metrics["validation_rate_percent"] == 50.0


def test_benchmark_scenarios_have_unique_ids():
    scenario_ids = [scenario["id"] for scenario in SCENARIOS]

    assert len(scenario_ids) == len(set(scenario_ids))


def test_benchmark_runs_without_external_services(tmp_path):
    report = run_benchmark(
        output_path=tmp_path / "benchmark.json",
        log_path=tmp_path / "benchmark.log",
    )

    metrics = report["metrics"]

    assert metrics["scenario_count"] == len(SCENARIOS)
    assert metrics["decision_accuracy_percent"] == 100.0
    assert metrics["attack_block_rate_percent"] == 100.0
    assert metrics["unsafe_allow_rate_percent"] == 0.0
    assert metrics["malicious_execution_rate_percent"] == 0.0
    assert metrics["false_positive_rate_percent"] == 0.0
    assert metrics["validation_rate_percent"] == 10.0

    report_file = tmp_path / "benchmark.json"
    assert report_file.exists()


def test_benchmark_records_expected_decisions():
    report = run_benchmark(output_path=None)

    assert all(
        result["decision_correct"]
        for result in report["results"]
    )

    assert all(
        not result["executed"]
        for result in report["results"]
        if result["category"] == "malicious"
    )