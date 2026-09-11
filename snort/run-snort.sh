#!/bin/sh
set -eu

PCAP_FILE=${PCAP_FILE:-lab-traffic.pcap}
OUTPUT_DIR=${OUTPUT_DIR:-/alerts}
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR/alert_json.txt"

status=0
/home/snorty/snort3/bin/snort \
  -q \
  -c /home/snorty/snort3/etc/snort/snort.lua \
  -R /rules/local.rules \
  -r "/evidence/$PCAP_FILE" \
  -k none \
  -A alert_json \
  -l "$OUTPUT_DIR" \
  --lua "alert_json = { file = true, fields = 'seconds timestamp iface proto src_addr src_port dst_addr dst_port pkt_len service action gid sid rev msg class priority' }" || status=$?

chmod -R a+rX "$OUTPUT_DIR"
exit "$status"
