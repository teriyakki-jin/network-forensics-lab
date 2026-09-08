#!/bin/sh
set -eu

PCAP_FILE=${PCAP_FILE:-lab-traffic.pcap}
OUTPUT_DIR=${OUTPUT_DIR:-/alerts/suricata}
output_dir=$OUTPUT_DIR
rm -rf "$output_dir"
mkdir -p "$output_dir"

exec suricata \
  --runmode single \
  -k none \
  -r "/evidence/$PCAP_FILE" \
  -S /rules/local.rules \
  -l "$output_dir"
