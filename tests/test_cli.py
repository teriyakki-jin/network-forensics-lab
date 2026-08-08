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
        self.assertEqual(payload["valid_rules"], 6)

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
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(normalised.read_text(encoding="utf-8").splitlines()), 2)
            payload = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(payload["totals"], {"snort": 1, "suricata": 1})


if __name__ == "__main__":
    unittest.main()
