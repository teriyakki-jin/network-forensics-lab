from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "forensics.cli", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


class ForensicsCliTests(unittest.TestCase):
    def test_verify_fixture_reports_hash_and_packet_count(self) -> None:
        result = _run_cli(
            "verify-fixture",
            "--pcap",
            "evidence/lab-traffic.pcap",
            "--checksum",
            "evidence/lab-traffic.pcap.sha256",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["integrity"]["matches"])
        self.assertGreater(payload["pcap"]["packets"], 0)
        self.assertEqual(payload["pcap"]["file_bytes"], payload["integrity"]["bytes"])

    def test_validate_sigma_checks_directory(self) -> None:
        result = _run_cli("validate-sigma", "--directory", "detection/sigma")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["valid_rules"], 8)

    def test_build_case_writes_manifest_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            pcap = evidence / "capture.pcap"
            alerts = evidence / "alerts.jsonl"
            pcap.write_bytes(b"fixture")
            alerts.write_text(
                json.dumps(
                    {
                        "@timestamp": "2026-09-08T06:00:00Z",
                        "engine": "snort",
                        "scenario": "doip_unauthorized_diagnostic",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = evidence / "case-manifest.json"
            timeline = evidence / "incident-timeline.json"

            result = _run_cli(
                "build-case",
                "--case-id",
                "NF-AUTO-LAB",
                "--evidence-root",
                str(evidence),
                "--artifact",
                str(pcap),
                "--artifact",
                str(alerts),
                "--normalised",
                str(alerts),
                "--acquired-at",
                "2026-09-08T06:00:00Z",
                "--sensor-id",
                "sensor-vehicle-gateway",
                "--tool-version",
                "snort=3",
                "--manifest",
                str(manifest),
                "--timeline",
                str(timeline),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            timeline_payload = json.loads(timeline.read_text(encoding="utf-8"))

        self.assertEqual(manifest_payload["case_id"], "NF-AUTO-LAB")
        self.assertEqual(len(manifest_payload["artifacts"]), 2)
        self.assertEqual(timeline_payload["events"][0]["sequence"], 1)

    def test_evaluate_writes_scenario_level_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alerts = root / "alerts.jsonl"
            truth = root / "ground-truth.json"
            output = root / "metrics.json"
            alerts.write_text(
                json.dumps({"engine": "snort", "scenario": "attack-a"}) + "\n",
                encoding="utf-8",
            )
            truth.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": [
                            {"scenario": "attack-a", "label": "attack"},
                            {"scenario": "normal-a", "label": "benign"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "evaluate",
                "--alerts",
                str(alerts),
                "--ground-truth",
                str(truth),
                "--engine",
                "snort",
                "--output",
                str(output),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["confusion_matrix"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        self.assertEqual(payload["metrics"]["recall"], 1.0)

    def test_compare_writes_normalised_records_and_report(self) -> None:
        snort = {
            "timestamp": "08/08-12:34:56.123456",
            "proto": "TCP",
            "src_addr": "10.77.0.20",
            "dst_addr": "10.77.0.10",
            "sid": 1000004,
        }
        suricata_alert = {
            "timestamp": "2026-08-08T12:34:56+0900",
            "event_type": "alert",
            "src_ip": "10.77.0.20",
            "dest_ip": "10.77.0.10",
            "proto": "TCP",
            "alert": {"signature_id": 1000004, "severity": 2},
        }
        suricata_flow = {"event_type": "flow"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snort_path = root / "snort.jsonl"
            suricata_path = root / "eve.json"
            normalised = root / "normalised.jsonl"
            report = root / "report.json"
            snort_path.write_text(json.dumps(snort) + "\n", encoding="utf-8")
            suricata_path.write_text(
                json.dumps(suricata_alert) + "\n" + json.dumps(suricata_flow) + "\n",
                encoding="utf-8",
            )

            result = _run_cli(
                "compare",
                "--catalog",
                str(ROOT / "detection" / "rule-catalog.json"),
                "--snort",
                str(snort_path),
                "--suricata",
                str(suricata_path),
                "--normalised",
                str(normalised),
                "--report",
                str(report),
                "--fixture-id",
                "attack",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(normalised.read_text(encoding="utf-8").splitlines()), 2)
            payload = json.loads(report.read_text(encoding="utf-8"))
            records = [json.loads(line) for line in normalised.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payload["totals"], {"snort": 1, "suricata": 1})
        self.assertEqual({record["fixture_id"] for record in records}, {"attack"})

    def test_aggregate_evaluations_writes_repeated_run_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = []
            for run_id in (1, 2):
                path = root / f"run-{run_id}.json"
                path.write_text(
                    json.dumps(
                        {
                            "run_id": run_id,
                            "engine": "snort",
                            "confusion_matrix": {"tp": 8, "fp": 0, "fn": 0, "tn": 8},
                        }
                    ),
                    encoding="utf-8",
                )
                inputs.extend(("--input", str(path)))
            output = root / "aggregate.json"

            result = _run_cli(
                "aggregate-evaluations", *inputs, "--output", str(output)
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["scope"]["repeated_runs"], 2)
        self.assertEqual(payload["engines"]["snort"]["observations"], 32)


if __name__ == "__main__":
    unittest.main()
