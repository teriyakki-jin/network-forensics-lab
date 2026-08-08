"""Public interfaces for the IDS comparison pipeline."""

from __future__ import annotations

import hashlib
import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


_CATALOG_REQUIRED = {
    "scenario",
    "title",
    "snort_sid",
    "suricata_sid",
    "attack",
}


def _validate_rule(rule: dict[str, Any]) -> None:
    missing = sorted(_CATALOG_REQUIRED - rule.keys())
    if missing:
        raise ValueError(f"catalog rule missing fields: {', '.join(missing)}")
    attack = rule["attack"]
    required_attack = {"tactic", "technique_id", "technique_name"}
    if not isinstance(attack, dict) or required_attack - attack.keys():
        raise ValueError("catalog rule attack mapping is incomplete")


def _unique_rules(catalog: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    by_scenario: dict[str, dict[str, Any]] = {}
    for rule in catalog.values():
        by_scenario[rule["scenario"]] = rule
    return [by_scenario[name] for name in sorted(by_scenario)]


def _normalised_record(
    *,
    engine: str,
    event: dict[str, Any],
    rule: dict[str, Any],
    source_ip_key: str,
    source_port_key: str,
    destination_ip_key: str,
    destination_port_key: str,
    transport_key: str,
    timestamp: Any,
    severity: Any = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "@timestamp": timestamp,
        "engine": engine,
        "scenario": rule["scenario"],
        "event": {"kind": "alert", "category": "intrusion_detection"},
        "rule": {
            "id": str(rule[f"{engine}_sid"]),
            "description": rule["title"],
        },
        "source": {
            "ip": event.get(source_ip_key),
            "port": event.get(source_port_key),
        },
        "destination": {
            "ip": event.get(destination_ip_key),
            "port": event.get(destination_port_key),
        },
        "network": {"transport": str(event.get(transport_key, "")).lower()},
        "observer": {"type": "ids", "product": engine},
        "threat": {
            "tactic": {"name": rule["attack"]["tactic"]},
            "technique": {
                "id": rule["attack"]["technique_id"],
                "name": rule["attack"]["technique_name"],
            },
        },
    }
    if severity is not None:
        record["event"]["severity"] = severity
    return record


def load_rule_catalog(path: Path) -> dict[str, dict[str, Any]]:
    """Load and validate the cross-engine detection rule catalog."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("rules"), list):
        raise ValueError("catalog schema_version must be 1 and rules must be a list")

    catalog: dict[str, dict[str, Any]] = {}
    scenarios: set[str] = set()
    for rule in payload["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("catalog rules must be objects")
        _validate_rule(rule)
        if rule["scenario"] in scenarios:
            raise ValueError(f"duplicate catalog scenario: {rule['scenario']}")
        scenarios.add(rule["scenario"])
        for engine in ("snort", "suricata"):
            sid = int(rule[f"{engine}_sid"])
            key = f"{engine}:{sid}"
            if key in catalog:
                raise ValueError(f"duplicate catalog SID: {key}")
            catalog[key] = rule
    return catalog


def normalise_snort(
    event: dict[str, Any], catalog: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Convert one Snort alert to the lab's engine-neutral evidence shape."""
    sid = int(event.get("sid", 0))
    rule = catalog.get(f"snort:{sid}")
    if rule is None:
        raise ValueError(f"unknown Snort SID: {sid}")
    seconds = event.get("seconds")
    timestamp = event.get("timestamp")
    if seconds is not None:
        timestamp = datetime.fromtimestamp(float(seconds), timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    return _normalised_record(
        engine="snort",
        event=event,
        rule=rule,
        source_ip_key="src_addr",
        source_port_key="src_port",
        destination_ip_key="dst_addr",
        destination_port_key="dst_port",
        transport_key="proto",
        timestamp=timestamp,
        severity=event.get("priority"),
    )


def normalise_suricata(
    event: dict[str, Any], catalog: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Convert one Suricata EVE alert, ignoring non-alert EVE events."""
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise ValueError("Suricata alert event is missing alert metadata")
    sid = int(alert.get("signature_id", 0))
    rule = catalog.get(f"suricata:{sid}")
    if rule is None:
        raise ValueError(f"unknown Suricata SID: {sid}")
    return _normalised_record(
        engine="suricata",
        event=event,
        rule=rule,
        source_ip_key="src_ip",
        source_port_key="src_port",
        destination_ip_key="dest_ip",
        destination_port_key="dest_port",
        transport_key="proto",
        timestamp=event.get("timestamp"),
        severity=alert.get("severity"),
    )


def build_comparison(
    snort_records: Iterable[dict[str, Any]],
    suricata_records: Iterable[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build deterministic per-scenario Snort/Suricata count evidence."""
    snort_counts = Counter(record["scenario"] for record in snort_records)
    suricata_counts = Counter(record["scenario"] for record in suricata_records)
    scenarios = []
    for rule in _unique_rules(catalog):
        scenario = rule["scenario"]
        snort_count = snort_counts[scenario]
        suricata_count = suricata_counts[scenario]
        scenarios.append(
            {
                "scenario": scenario,
                "title": rule["title"],
                "attack": rule["attack"],
                "snort_alerts": snort_count,
                "suricata_alerts": suricata_count,
                "delta": snort_count - suricata_count,
                "detected_by_both": snort_count > 0 and suricata_count > 0,
            }
        )
    return {
        "schema_version": 1,
        "totals": {
            "snort": sum(snort_counts.values()),
            "suricata": sum(suricata_counts.values()),
        },
        "scenarios": scenarios,
    }


def verify_pcap_hash(pcap_path: Path, checksum_path: Path) -> dict[str, Any]:
    """Verify a PCAP against a sha256sum-compatible checksum file."""
    checksum_parts = checksum_path.read_text(encoding="ascii").strip().split()
    if not checksum_parts:
        raise ValueError("checksum file is empty")
    expected = checksum_parts[0].lower()
    content = pcap_path.read_bytes()
    actual = hashlib.sha256(content).hexdigest()
    return {
        "path": pcap_path.name,
        "bytes": len(content),
        "algorithm": "sha256",
        "expected": expected,
        "actual": actual,
        "matches": actual == expected,
    }


def inspect_pcap(pcap_path: Path) -> dict[str, Any]:
    """Return deterministic packet and byte counts for a classic PCAP fixture."""
    content = pcap_path.read_bytes()
    if len(content) < 24:
        raise ValueError("PCAP global header is truncated")
    magic = content[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
        b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
    }
    if magic not in formats:
        raise ValueError("PCAP magic number is unsupported")
    endian, timestamp_precision = formats[magic]
    _, major, minor, _, _, snaplen, link_type = struct.unpack(
        f"{endian}IHHIIII", content[:24]
    )
    if (major, minor) != (2, 4):
        raise ValueError(f"PCAP version is unsupported: {major}.{minor}")

    offset = 24
    packets = 0
    captured_bytes = 0
    original_bytes = 0
    while offset < len(content):
        if len(content) - offset < 16:
            raise ValueError("PCAP packet header is truncated")
        _, _, included_length, original_length = struct.unpack(
            f"{endian}IIII", content[offset : offset + 16]
        )
        offset += 16
        packet_end = offset + included_length
        if packet_end > len(content):
            raise ValueError("PCAP packet data is truncated")
        packets += 1
        captured_bytes += included_length
        original_bytes += original_length
        offset = packet_end

    return {
        "path": pcap_path.name,
        "format": "pcap",
        "version": f"{major}.{minor}",
        "timestamp_precision": timestamp_precision,
        "snaplen": snaplen,
        "link_type": link_type,
        "packets": packets,
        "captured_bytes": captured_bytes,
        "original_bytes": original_bytes,
        "file_bytes": len(content),
    }


def validate_sigma_rule(path: Path) -> dict[str, Any]:
    """Validate the required portable fields of one Sigma rule."""
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Sigma rule must be a mapping")
    required = {"title", "id", "status", "logsource", "detection", "level", "tags"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"Sigma rule missing fields: {', '.join(missing)}")
    if not isinstance(payload["detection"], dict) or "condition" not in payload["detection"]:
        raise ValueError("Sigma detection must include a condition")
    tags = payload["tags"]
    if not isinstance(tags, list):
        raise ValueError("Sigma tags must be a list")
    techniques = sorted(
        str(tag).split(".", 1)[1].upper()
        for tag in tags
        if str(tag).lower().startswith("attack.t")
    )
    if not techniques:
        raise ValueError("Sigma rule must include an attack technique tag")
    return {
        "path": path.name,
        "title": payload["title"],
        "id": str(payload["id"]),
        "level": str(payload["level"]),
        "techniques": techniques,
    }
