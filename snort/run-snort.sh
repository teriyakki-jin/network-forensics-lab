#!/bin/sh
set -eu

rm -f /alerts/alert_json.txt

exec /home/snorty/snort3/bin/snort \
  -q \
  -c /home/snorty/snort3/etc/snort/snort.lua \
  -R /rules/local.rules \
  -r /evidence/lab-traffic.pcap \
  -k none \
  -A alert_json \
  -l /alerts \
  --lua "alert_json = { file = true, fields = 'seconds timestamp iface proto src_addr src_port dst_addr dst_port pkt_len service action gid sid rev msg class priority' }"
