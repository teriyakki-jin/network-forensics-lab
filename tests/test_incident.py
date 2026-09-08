from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from forensics.incident import (
    aggregate_evaluations,
    build_case_manifest,
    build_timeline,
    evaluate_detection,
)


class DetectionEvaluationTests(unittest.TestCase):
    def test_calculates_scenario_level_metrics_from_ground_truth(self) -> None:
        ground_truth = [
            {"scenario": "doip_unauthorized_diagnostic", "label": "attack"},
            {"scenario": "someip_service_discovery", "label": "attack"},
            {"scenario": "normal_doip_session", "label": "benign"},
            {"scenario": "normal_someip_heartbeat", "label": "benign"},
        ]
        alerts = [
            {"engine": "snort", "scenario": "doip_unauthorized_diagnostic"},
            {"engine": "snort", "scenario": "normal_someip_heartbeat"},
        ]

        result = evaluate_detection(alerts, ground_truth, engine="snort")

        self.assertEqual(result["unit"], "scenario")
        self.assertEqual(result["confusion_matrix"], {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
        self.assertEqual(result["metrics"]["recall"], 0.5)
        self.assertEqual(result["metrics"]["precision"], 0.5)
        self.assertEqual(result["metrics"]["false_positive_rate"], 0.5)

    def test_rejects_duplicate_or_unknown_ground_truth_labels(self) -> None:
        duplicate = [
            {"scenario": "same", "label": "attack"},
            {"scenario": "same", "label": "benign"},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate_detection([], duplicate, engine="snort")
        with self.assertRaisesRegex(ValueError, "label"):
            evaluate_detection([], [{"scenario": "bad", "label": "unknown"}], engine="snort")

    def test_scores_the_same_scenario_independently_for_attack_and_benign_fixtures(self) -> None:
        ground_truth = [
            {"fixture_id": "attack", "scenario": "doip", "label": "attack"},
            {"fixture_id": "benign", "scenario": "doip", "label": "benign"},
        ]
        alerts = [
            {"fixture_id": "attack", "engine": "snort", "scenario": "doip"},
        ]

        result = evaluate_detection(alerts, ground_truth, engine="snort")

        self.assertEqual(result["confusion_matrix"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        self.assertEqual(result["scope"]["ground_truth_cases"], 2)
        self.assertEqual(result["scope"]["ground_truth_scenarios"], 1)
        self.assertEqual(
            result["scope"]["detected_cases"],
            [{"fixture_id": "attack", "scenario": "doip"}],
        )


class EvaluationAggregationTests(unittest.TestCase):
    def test_aggregates_repeated_runs_without_inflating_unique_scenarios(self) -> None:
        reports = []
        for run_id in (1, 2):
            for engine in ("snort", "suricata"):
                reports.append(
                    {
                        "run_id": run_id,
                        "engine": engine,
                        "confusion_matrix": {"tp": 8, "fp": 0, "fn": 0, "tn": 8},
                        "scope": {"ground_truth_cases": 16},
                    }
                )

        result = aggregate_evaluations(reports)

        self.assertEqual(result["scope"]["repeated_runs"], 2)
        self.assertEqual(result["scope"]["unique_attack_scenarios"], 8)
        self.assertEqual(result["scope"]["unique_benign_scenarios"], 8)
        self.assertEqual(result["engines"]["snort"]["observations"], 32)
        self.assertEqual(result["engines"]["snort"]["metrics"]["recall"], 1.0)
        self.assertEqual(result["engines"]["suricata"]["repeatability"], "2/2")


class CaseManifestTests(unittest.TestCase):
    def test_hashes_every_artifact_and_records_acquisition_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "capture.pcap"
            report = root / "report.json"
            pcap.write_bytes(b"pcap-evidence")
            report.write_text('{"ok": true}\n', encoding="utf-8")

            result = build_case_manifest(
                case_id="NF-2026-001",
                evidence_root=root,
                artifacts=[pcap, report],
                acquired_at="2026-09-08T06:00:00Z",
                sensor_id="sensor-ot-gateway",
                tool_versions={"snort": "3", "suricata": "8"},
            )

        self.assertEqual(result["case_id"], "NF-2026-001")
        self.assertEqual(result["acquisition"]["sensor_id"], "sensor-ot-gateway")
        self.assertEqual([item["path"] for item in result["artifacts"]], ["capture.pcap", "report.json"])
        self.assertEqual(result["artifacts"][0]["sha256"], hashlib.sha256(b"pcap-evidence").hexdigest())

    def test_rejects_artifact_outside_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            foreign = Path(outside) / "foreign.bin"
            foreign.write_bytes(b"foreign")
            with self.assertRaisesRegex(ValueError, "outside evidence root"):
                build_case_manifest(
                    case_id="NF-2026-002",
                    evidence_root=root,
                    artifacts=[foreign],
                    acquired_at="2026-09-08T06:00:00Z",
                    sensor_id="sensor-1",
                    tool_versions={},
                )


class TimelineTests(unittest.TestCase):
    def test_sorts_alerts_and_preserves_evidence_references(self) -> None:
        records = [
            {"@timestamp": "2026-09-08T06:00:03Z", "engine": "snort", "scenario": "doip_unauthorized_diagnostic"},
            {"@timestamp": "2026-09-08T06:00:01Z", "engine": "suricata", "scenario": "someip_service_discovery"},
        ]

        result = build_timeline(records)

        self.assertEqual(result[0]["sequence"], 1)
        self.assertEqual(result[0]["scenario"], "someip_service_discovery")
        self.assertEqual(result[1]["sequence"], 2)


if __name__ == "__main__":
    unittest.main()
