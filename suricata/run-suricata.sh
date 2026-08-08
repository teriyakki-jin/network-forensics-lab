#!/bin/sh
set -eu

output_dir=/alerts/suricata
rm -rf "$output_dir"
mkdir -p "$output_dir"

exec suricata \
  --runmode single \
  -k none \
  -r /evidence/lab-traffic.pcap \
  -S /rules/local.rules \
  -l "$output_dir"
