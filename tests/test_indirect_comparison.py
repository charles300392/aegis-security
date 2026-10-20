"""Tests for the AEGIS indirect-injection comparison benchmark."""

from benchmark.indirect_comparison import (
    SCENARIOS,
    run_comparison,
)


def test_indirect_scenario_ids_are_unique():
    ids = [scenario["id"] for scenario in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_comparison_contains_attacks_and_controls():
    categories = {scenario["category"] for scenario in SCENARIOS}

    assert categories == {"malicious", "legitimate"}


def test_aegis_blocks_simulated_indirect_attack_actions():
    report = run_comparison(output_path=None)

    attacks = [
        result
        for result in report["results"]
        if result["category"] == "malicious"
    ]

    assert attacks

    for result in attacks:
        assert result["baseline"]["executed"] is True
        assert result["protected"]["decision"] == "BLOCK"
        assert result["protected"]["executed"] is False
        assert result["protection_effective"] is True


def test_aegis_allows_legitimate_control_requests():
    report = run_comparison(output_path=None)

    legitimate = [
        result
        for result in report["results"]
        if result["category"] == "legitimate"
    ]

    assert legitimate

    for result in legitimate:
        assert result["protected"]["decision"] == "ALLOW"
        assert result["protected"]["executed"] is True
        assert result["protection_effective"] is True


def test_comparison_metrics_match_expected_simulation():
    report = run_comparison(output_path=None)
    metrics = report["metrics"]

    assert metrics["scenario_count"] == 4
    assert metrics[
        "baseline_simulated_attack_execution_rate_percent"
    ] == 100.0
    assert metrics[
        "protected_malicious_execution_rate_percent"
    ] == 0.0
    assert metrics["protected_attack_prevention_rate_percent"] == 100.0
    assert metrics["legitimate_false_positive_rate_percent"] == 0.0
    assert metrics["legitimate_execution_rate_percent"] == 100.0


def test_comparison_report_can_be_saved(tmp_path):
    report_path = tmp_path / "comparison.json"

    report = run_comparison(output_path=report_path)

    assert report_path.exists()
    assert report["report_path"] == str(report_path.resolve())

    saved_report = report_path.read_text(encoding="utf-8")
    assert "deterministic_simulation" in saved_report