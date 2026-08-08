from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml

from forensics.pipeline import load_rule_catalog, validate_sigma_rule


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SCENARIOS = {
    "icmp_echo",
    "http_admin_probe",
    "tcp_syn_scan",
    "brute_force",
    "dns_tunneling",
    "web_exploit",
}


class ComposeSecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))

    def test_attack_network_is_internal_and_uses_fixed_private_subnet(self) -> None:
        lab_net = self.compose["networks"]["lab_net"]
        self.assertTrue(lab_net["internal"])
        self.assertEqual(lab_net["ipam"]["config"][0]["subnet"], "10.77.0.0/24")

    def test_dns_and_both_offline_ids_services_are_declared(self) -> None:
        services = self.compose["services"]
        self.assertEqual(services["dns"]["networks"]["lab_net"]["ipv4_address"], "10.77.0.53")
        for engine in ("snort", "suricata"):
            self.assertEqual(services[engine]["network_mode"], "none")
            self.assertIn("tools", services[engine]["profiles"])

    def test_container_images_and_base_image_do_not_use_latest_tags(self) -> None:
        for service, config in self.compose["services"].items():
            image = config.get("image")
            if image:
                self.assertFalse(image.endswith(":latest"), msg=f"{service} image must be version pinned")
                self.assertTrue(
                    ":" in image.rsplit("/", 1)[-1] or "@sha256:" in image,
                    msg=f"{service} image must include a version or digest",
                )
        dockerfile = (ROOT / "kali" / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn(":latest", dockerfile)
        self.assertRegex(
            dockerfile.splitlines()[0],
            r"^FROM .+(?::[0-9]{4}\.[0-9]+|@sha256:[0-9a-f]{64})$",
        )


class DetectionContentContractTests(unittest.TestCase):
    def test_catalog_contains_six_mapped_scenarios(self) -> None:
        catalog_path = ROOT / "detection" / "rule-catalog.json"
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
        scenarios = {rule["scenario"] for rule in payload["rules"]}
        self.assertEqual(scenarios, EXPECTED_SCENARIOS)
        catalog = load_rule_catalog(catalog_path)
        self.assertEqual(len(catalog), 12)

    def test_snort_and_suricata_rules_cover_every_catalog_sid(self) -> None:
        payload = json.loads(
            (ROOT / "detection" / "rule-catalog.json").read_text(encoding="utf-8")
        )
        snort_rules = (ROOT / "snort" / "local.rules").read_text(encoding="utf-8")
        suricata_rules = (ROOT / "suricata" / "local.rules").read_text(encoding="utf-8")
        for rule in payload["rules"]:
            self.assertIn(f"sid:{rule['snort_sid']};", snort_rules)
            self.assertIn(f"sid:{rule['suricata_sid']};", suricata_rules)

    def test_one_sigma_rule_exists_for_each_scenario(self) -> None:
        sigma_paths = sorted((ROOT / "detection" / "sigma").glob("*.yml"))
        self.assertEqual(len(sigma_paths), len(EXPECTED_SCENARIOS))
        technique_ids = set()
        for path in sigma_paths:
            result = validate_sigma_rule(path)
            technique_ids.update(result["techniques"])
        self.assertTrue({"T1110", "T1071.004", "T1190", "T1046"} <= technique_ids)


class AutomationContractTests(unittest.TestCase):
    def test_workflow_pins_actions_and_runs_regression_tests(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        action_uses = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertTrue(action_uses)
        for action in action_uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn("coverage run --branch", workflow)
        self.assertIn("verify-fixture", workflow)
        self.assertIn("validate-sigma", workflow)

    def test_run_script_generates_all_authorized_scenarios(self) -> None:
        script = (ROOT / "scripts" / "run-lab.ps1").read_text(encoding="utf-8")
        for marker in (
            "ICMP",
            "HTTP admin probe",
            "SYN scan",
            "brute force",
            "DNS tunneling",
            "web exploit",
        ):
            self.assertIn(marker, script)
        self.assertIn("run-comparison.ps1", script)

    def test_run_script_waits_for_elasticsearch_before_using_index_api(self) -> None:
        script = (ROOT / "scripts" / "run-lab.ps1").read_text(encoding="utf-8")
        health_check = script.index("/_cluster/health")
        index_delete = script.index("ids-alerts-*")
        self.assertLess(health_check, index_delete)
        self.assertIn("Elasticsearch did not become ready", script)
        self.assertIn("/_cat/indices/ids-alerts-*", script)
        self.assertNotIn(
            "-Method Delete -Uri 'http://127.0.0.1:9200/ids-alerts-*'", script
        )

    def test_kibana_setup_creates_repeatable_lens_dashboard(self) -> None:
        script = (ROOT / "scripts" / "setup-kibana.ps1").read_text(encoding="utf-8")
        self.assertIn("network-forensics-overview", script)
        self.assertIn("/api/dashboards/$DashboardId", script)
        for field in (
            "engine.keyword",
            "scenario.keyword",
            "threat.technique.id.keyword",
            "source.ip.keyword",
            "destination.ip.keyword",
        ):
            self.assertIn(field, script)
        self.assertGreaterEqual(script.count("type          = 'vis'"), 5)

        capture = (ROOT / "scripts" / "capture-kibana.mjs").read_text(
            encoding="utf-8"
        )
        self.assertIn("network-forensics-overview", capture)
        self.assertIn("kibana-lens-dashboard.png", capture)


if __name__ == "__main__":
    unittest.main()
