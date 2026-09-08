"""Incident evaluation, timeline, and chain-of-custody evidence helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate_detection(
    alerts: Iterable[dict[str, Any]],
    ground_truth: Iterable[dict[str, str]],
    *,
    engine: str,
) -> dict[str, Any]:
    """Calculate scenario-level metrics without treating alert volume as accuracy."""
    truth: dict[tuple[str, str], str] = {}
    for item in ground_truth:
        fixture_id = item.get("fixture_id", "default")
        scenario = item.get("scenario", "")
        label = item.get("label", "")
        if not fixture_id:
            raise ValueError("ground-truth fixture_id is required")
        if not scenario:
            raise ValueError("ground-truth scenario is required")
        case = (fixture_id, scenario)
        if case in truth:
            raise ValueError(f"duplicate ground-truth case: {fixture_id}/{scenario}")
        if label not in {"attack", "benign"}:
            raise ValueError(f"ground-truth label must be attack or benign: {label}")
        truth[case] = label

    detected = {
        (str(alert.get("fixture_id", "default")), str(alert["scenario"]))
        for alert in alerts
        if alert.get("engine") == engine and alert.get("scenario")
    }
    tp = sum(label == "attack" and case in detected for case, label in truth.items())
    fn = sum(label == "attack" and case not in detected for case, label in truth.items())
    fp = sum(label == "benign" and case in detected for case, label in truth.items())
    tn = sum(label == "benign" and case not in detected for case, label in truth.items())
    detected_cases = sorted(detected & truth.keys())
    unscored_cases = sorted(detected - truth.keys())

    return {
        "schema_version": 1,
        "engine": engine,
        "unit": "scenario",
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {
            "recall": _ratio(tp, tp + fn),
            "precision": _ratio(tp, tp + fp),
            "false_positive_rate": _ratio(fp, fp + tn),
        },
        "scope": {
            "ground_truth_cases": len(truth),
            "ground_truth_scenarios": len({scenario for _, scenario in truth}),
            "detected_cases": [
                {"fixture_id": fixture_id, "scenario": scenario}
                for fixture_id, scenario in detected_cases
            ],
            "detected_scenarios": sorted({scenario for _, scenario in detected_cases}),
            "unscored_alert_cases": [
                {"fixture_id": fixture_id, "scenario": scenario}
                for fixture_id, scenario in unscored_cases
            ],
            "unscored_alert_scenarios": sorted({scenario for _, scenario in unscored_cases}),
        },
    }


def aggregate_evaluations(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate repeated paired-fixture runs without inflating unique scenario scope."""
    items = list(reports)
    if not items:
        raise ValueError("at least one evaluation report is required")

    engines: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for report in items:
        engine = str(report.get("engine", ""))
        run_id = str(report.get("run_id", ""))
        if not engine or not run_id:
            raise ValueError("each evaluation requires engine and run_id")
        key = (engine, run_id)
        if key in seen:
            raise ValueError(f"duplicate evaluation run: {engine}/{run_id}")
        seen.add(key)
        engines.setdefault(engine, []).append(report)

    run_sets = [{str(item["run_id"]) for item in reports} for reports in engines.values()]
    if any(run_ids != run_sets[0] for run_ids in run_sets[1:]):
        raise ValueError("all engines must contain the same run IDs")

    first_matrix = items[0]["confusion_matrix"]
    unique_attack = int(first_matrix["tp"]) + int(first_matrix["fn"])
    unique_benign = int(first_matrix["fp"]) + int(first_matrix["tn"])
    for report in items[1:]:
        matrix = report["confusion_matrix"]
        if int(matrix["tp"]) + int(matrix["fn"]) != unique_attack:
            raise ValueError("attack scenario scope changed between runs")
        if int(matrix["fp"]) + int(matrix["tn"]) != unique_benign:
            raise ValueError("benign scenario scope changed between runs")

    engine_results: dict[str, Any] = {}
    for engine, engine_reports in sorted(engines.items()):
        totals = {
            name: sum(int(report["confusion_matrix"][name]) for report in engine_reports)
            for name in ("tp", "fp", "fn", "tn")
        }
        successful = sum(
            int(report["confusion_matrix"]["fp"]) == 0
            and int(report["confusion_matrix"]["fn"]) == 0
            for report in engine_reports
        )
        engine_results[engine] = {
            "observations": sum(totals.values()),
            "confusion_matrix": totals,
            "metrics": {
                "recall": _ratio(totals["tp"], totals["tp"] + totals["fn"]),
                "precision": _ratio(totals["tp"], totals["tp"] + totals["fp"]),
                "false_positive_rate": _ratio(totals["fp"], totals["fp"] + totals["tn"]),
            },
            "repeatability": f"{successful}/{len(engine_reports)}",
        }

    return {
        "schema_version": 1,
        "unit": "paired_fixture_scenario_observation",
        "scope": {
            "repeated_runs": len(run_sets[0]),
            "unique_attack_scenarios": unique_attack,
            "unique_benign_scenarios": unique_benign,
        },
        "engines": engine_results,
    }


def build_case_manifest(
    *,
    case_id: str,
    evidence_root: Path,
    artifacts: Iterable[Path],
    acquired_at: str,
    sensor_id: str,
    tool_versions: dict[str, str],
) -> dict[str, Any]:
    """Hash evidence artifacts and record their acquisition provenance."""
    if not case_id or not acquired_at or not sensor_id:
        raise ValueError("case_id, acquired_at, and sensor_id are required")
    root = evidence_root.resolve()
    entries = []
    for artifact in artifacts:
        resolved = artifact.resolve()
        try:
            relative = resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"artifact is outside evidence root: {artifact}") from exc
        if not resolved.is_file():
            raise ValueError(f"artifact is not a file: {artifact}")
        content = resolved.read_bytes()
        entries.append(
            {
                "path": relative.as_posix(),
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    return {
        "schema_version": 1,
        "case_id": case_id,
        "acquisition": {
            "acquired_at": acquired_at,
            "sensor_id": sensor_id,
            "timezone": "UTC",
        },
        "tool_versions": dict(sorted(tool_versions.items())),
        "artifacts": sorted(entries, key=lambda item: item["path"]),
    }


def build_timeline(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a deterministic evidence timeline from normalised alerts."""
    ordered = sorted(records, key=lambda record: (str(record.get("@timestamp", "")), str(record.get("engine", ""))))
    return [
        {
            "sequence": sequence,
            "timestamp": record.get("@timestamp"),
            "engine": record.get("engine"),
            "scenario": record.get("scenario"),
            "source": record.get("source"),
            "destination": record.get("destination"),
            "rule": record.get("rule"),
        }
        for sequence, record in enumerate(ordered, 1)
    ]
