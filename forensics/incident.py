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
    truth: dict[str, str] = {}
    for item in ground_truth:
        scenario = item.get("scenario", "")
        label = item.get("label", "")
        if not scenario:
            raise ValueError("ground-truth scenario is required")
        if scenario in truth:
            raise ValueError(f"duplicate ground-truth scenario: {scenario}")
        if label not in {"attack", "benign"}:
            raise ValueError(f"ground-truth label must be attack or benign: {label}")
        truth[scenario] = label

    detected = {
        str(alert["scenario"])
        for alert in alerts
        if alert.get("engine") == engine and alert.get("scenario")
    }
    tp = sum(label == "attack" and scenario in detected for scenario, label in truth.items())
    fn = sum(label == "attack" and scenario not in detected for scenario, label in truth.items())
    fp = sum(label == "benign" and scenario in detected for scenario, label in truth.items())
    tn = sum(label == "benign" and scenario not in detected for scenario, label in truth.items())

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
            "ground_truth_scenarios": len(truth),
            "detected_scenarios": sorted(detected & truth.keys()),
            "unscored_alert_scenarios": sorted(detected - truth.keys()),
        },
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
