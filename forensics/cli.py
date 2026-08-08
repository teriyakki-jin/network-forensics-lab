"""Command-line entrypoint for deterministic network-forensics evidence checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Sequence

from .pipeline import (
    build_comparison,
    inspect_pcap,
    load_rule_catalog,
    normalise_snort,
    normalise_suricata,
    validate_sigma_rule,
    verify_pcap_hash,
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"{path}:{line_number} must contain a JSON object")
        records.append(payload)
    return records


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _compare(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_rule_catalog(args.catalog)
    snort_records = [normalise_snort(event, catalog) for event in _read_jsonl(args.snort)]
    suricata_records = []
    for event in _read_jsonl(args.suricata):
        record = normalise_suricata(event, catalog)
        if record is not None:
            suricata_records.append(record)
    report = build_comparison(snort_records, suricata_records, catalog)
    _write_jsonl(args.normalised, snort_records + suricata_records)
    _write_json(args.report, report)
    return report


def _verify_fixture(args: argparse.Namespace) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "integrity": verify_pcap_hash(args.pcap, args.checksum),
        "pcap": inspect_pcap(args.pcap),
    }
    if not payload["integrity"]["matches"]:
        raise ValueError("PCAP checksum does not match")
    if args.output is not None:
        _write_json(args.output, payload)
    return payload


def _validate_sigma(args: argparse.Namespace) -> dict[str, Any]:
    rules = [validate_sigma_rule(path) for path in sorted(args.directory.glob("*.yml"))]
    if not rules:
        raise ValueError(f"no Sigma rules found in {args.directory}")
    payload = {"schema_version": 1, "valid_rules": len(rules), "rules": rules}
    if args.output is not None:
        _write_json(args.output, payload)
    return payload


def _path(value: str) -> Path:
    return Path(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    compare = subparsers.add_parser("compare", help="normalise and compare IDS alerts")
    compare.add_argument("--catalog", type=_path, required=True)
    compare.add_argument("--snort", type=_path, required=True)
    compare.add_argument("--suricata", type=_path, required=True)
    compare.add_argument("--normalised", type=_path, required=True)
    compare.add_argument("--report", type=_path, required=True)
    compare.set_defaults(handler=_compare)

    fixture = subparsers.add_parser("verify-fixture", help="verify PCAP integrity and structure")
    fixture.add_argument("--pcap", type=_path, required=True)
    fixture.add_argument("--checksum", type=_path, required=True)
    fixture.add_argument("--output", type=_path)
    fixture.set_defaults(handler=_verify_fixture)

    sigma = subparsers.add_parser("validate-sigma", help="validate Sigma rule metadata")
    sigma.add_argument("--directory", type=_path, required=True)
    sigma.add_argument("--output", type=_path)
    sigma.set_defaults(handler=_validate_sigma)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], dict[str, Any]] = args.handler
    payload = handler(args)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
