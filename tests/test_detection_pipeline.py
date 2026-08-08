from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from forensics.pipeline import (
    build_comparison,
    inspect_pcap,
    load_rule_catalog,
    normalise_snort,
    normalise_suricata,
    validate_sigma_rule,
    verify_pcap_hash,
)


CATALOG_DATA = {
    "schema_version": 1,
    "rules": [
        {
            "scenario": "brute_force",
            "title": "LAB HTTP Basic Auth Brute Force",
            "snort_sid": 1000004,
            "suricata_sid": 1000004,
            "attack": {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
            },
        },
        {
            "scenario": "dns_tunneling",
            "title": "LAB DNS Tunneling Pattern",
            "snort_sid": 1000005,
            "suricata_sid": 1000005,
            "attack": {
                "tactic": "Command and Control",
                "technique_id": "T1071.004",
                "technique_name": "DNS",
            },
        },
    ],
}


def _catalog_file(root: Path, payload: dict = CATALOG_DATA) -> Path:
    path = root / "catalog.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class RuleCatalogTests(unittest.TestCase):
    def test_loads_catalog_and_indexes_both_engine_sids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = load_rule_catalog(_catalog_file(Path(tmp)))

        self.assertEqual(catalog["snort:1000004"]["scenario"], "brute_force")
        self.assertEqual(catalog["suricata:1000005"]["attack"]["technique_id"], "T1071.004")

    def test_rejects_catalog_rule_without_attack_mapping(self) -> None:
        broken = {
            "schema_version": 1,
            "rules": [{"scenario": "bad", "title": "bad", "snort_sid": 1, "suricata_sid": 1}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "attack"):
                load_rule_catalog(_catalog_file(Path(tmp), broken))


class NormalisationTests(unittest.TestCase):
    def setUp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.catalog = load_rule_catalog(_catalog_file(Path(tmp)))

    def test_normalises_snort_without_copying_credentials(self) -> None:
        event = {
            "seconds": 1786198223,
            "timestamp": "08/08-12:34:56.123456",
            "proto": "TCP",
            "src_addr": "10.77.0.20",
            "src_port": 50123,
            "dst_addr": "10.77.0.10",
            "dst_port": 80,
            "sid": 1000004,
            "msg": "LAB HTTP Basic Auth Brute Force",
            "authorization": "Basic ZGVtbzpiYWQ=",
        }

        result = normalise_snort(event, self.catalog)

        self.assertEqual(result["engine"], "snort")
        self.assertEqual(result["scenario"], "brute_force")
        self.assertEqual(result["threat"]["technique"]["id"], "T1110")
        self.assertEqual(result["source"]["ip"], "10.77.0.20")
        self.assertEqual(result["@timestamp"], "2026-08-08T14:10:23Z")
        self.assertNotIn("authorization", json.dumps(result).lower())
        self.assertNotIn("ZGVtbzpiYWQ=", json.dumps(result))

    def test_normalises_suricata_alert_and_ignores_flow_events(self) -> None:
        alert = {
            "timestamp": "2026-08-08T12:34:56.123456+0900",
            "event_type": "alert",
            "src_ip": "10.77.0.20",
            "src_port": 53000,
            "dest_ip": "10.77.0.53",
            "dest_port": 53,
            "proto": "UDP",
            "alert": {
                "signature_id": 1000005,
                "signature": "LAB DNS Tunneling Pattern",
                "severity": 2,
            },
        }

        result = normalise_suricata(alert, self.catalog)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["engine"], "suricata")
        self.assertEqual(result["scenario"], "dns_tunneling")
        self.assertEqual(result["network"]["transport"], "udp")
        self.assertIsNone(normalise_suricata({"event_type": "flow"}, self.catalog))

    def test_unknown_sid_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown Snort SID"):
            normalise_snort({"sid": 9999999}, self.catalog)


class ComparisonTests(unittest.TestCase):
    def test_reports_count_delta_for_every_catalog_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = load_rule_catalog(_catalog_file(Path(tmp)))
        snort = [
            {"scenario": "brute_force"},
            {"scenario": "brute_force"},
            {"scenario": "dns_tunneling"},
        ]
        suricata = [
            {"scenario": "brute_force"},
            {"scenario": "dns_tunneling"},
            {"scenario": "dns_tunneling"},
        ]

        report = build_comparison(snort, suricata, catalog)

        by_scenario = {item["scenario"]: item for item in report["scenarios"]}
        self.assertEqual(by_scenario["brute_force"]["snort_alerts"], 2)
        self.assertEqual(by_scenario["brute_force"]["delta"], 1)
        self.assertEqual(by_scenario["dns_tunneling"]["delta"], -1)
        self.assertEqual(report["totals"], {"snort": 3, "suricata": 3})


class EvidenceValidationTests(unittest.TestCase):
    def test_inspects_classic_pcap_packet_headers(self) -> None:
        global_header = struct.pack(
            "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
        )
        packet_one = struct.pack("<IIII", 1, 0, 4, 4) + b"abcd"
        packet_two = struct.pack("<IIII", 2, 0, 3, 3) + b"xyz"
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "fixture.pcap"
            pcap.write_bytes(global_header + packet_one + packet_two)
            result = inspect_pcap(pcap)

        self.assertEqual(result["packets"], 2)
        self.assertEqual(result["captured_bytes"], 7)
        self.assertEqual(result["link_type"], 1)

    def test_rejects_truncated_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "broken.pcap"
            pcap.write_bytes(b"not-a-pcap")
            with self.assertRaisesRegex(ValueError, "PCAP"):
                inspect_pcap(pcap)

    def test_verifies_sha256sum_file_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "fixture.pcap"
            pcap.write_bytes(b"pcap fixture")
            digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
            checksum = root / "fixture.pcap.sha256"
            checksum.write_text(f"{digest}  fixture.pcap\n", encoding="ascii")

            valid = verify_pcap_hash(pcap, checksum)
            pcap.write_bytes(b"tampered")
            invalid = verify_pcap_hash(pcap, checksum)

        self.assertTrue(valid["matches"])
        self.assertEqual(valid["bytes"], 12)
        self.assertFalse(invalid["matches"])

    def test_validates_sigma_required_fields(self) -> None:
        valid_sigma = """
title: LAB DNS Tunneling Alert
id: 27c7de28-a3dc-4e1d-9ea2-aae18812a7be
status: test
logsource:
  category: network_detection
detection:
  selection:
    rule.id: '1000005'
  condition: selection
level: high
tags:
  - attack.command-and-control
  - attack.t1071.004
"""
        invalid_sigma = "title: incomplete\nstatus: test\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid_path = root / "valid.yml"
            invalid_path = root / "invalid.yml"
            valid_path.write_text(valid_sigma, encoding="utf-8")
            invalid_path.write_text(invalid_sigma, encoding="utf-8")

            result = validate_sigma_rule(valid_path)
            with self.assertRaisesRegex(ValueError, "missing"):
                validate_sigma_rule(invalid_path)

        self.assertEqual(result["techniques"], ["T1071.004"])
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["path"], "valid.yml")


if __name__ == "__main__":
    unittest.main()
