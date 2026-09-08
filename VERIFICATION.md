# 실습 검증 결과

검증일: 2026-09-08 (Asia/Seoul)

## 최종 상태

| 항목 | 결과 |
|---|---|
| Docker 격리망 | `10.77.0.0/24`, `internal: true` |
| Kali → Nginx/CoreDNS/차량 Gateway 트래픽 | 8개 허가 시나리오 성공 |
| PCAP 수집 | 168 packets, 16,756 bytes |
| PCAP SHA-256 | 일치 |
| Snort 3 분석 | 45 alerts |
| Suricata 8 분석 | 45 alerts |
| 교차 탐지 | 8/8 시나리오, 모든 delta 0 |
| Sigma | 8 rules valid |
| 사건 증거 | 5 artifacts hashed, 90 timeline events |
| Elasticsearch | 90 documents |
| Kibana | `available`, Lens dashboard 7 panels |
| Python test | 34 passed, branch coverage 포함 전체 93% |

## 탐지 결과

| SID | 시나리오 | ATT&CK | Snort | Suricata |
|---|---|---|---:|---:|
| `1000001` | `icmp_echo` | T1018 | 3 | 3 |
| `1000002` | `http_admin_probe` | T1190 | 1 | 1 |
| `1000003` | `tcp_syn_scan` | T1046 | 33 | 33 |
| `1000004` | `brute_force` | T1110 | 1 | 1 |
| `1000005` | `dns_tunneling` | T1071.004 | 4 | 4 |
| `1000006` | `web_exploit` | T1190 | 1 | 1 |
| `1000007` | `doip_unauthorized_diagnostic` | T1692.001 | 1 | 1 |
| `1000008` | `someip_service_discovery` | T0846.003 | 1 | 1 |
| **합계** |  |  | **45** | **45** |

## 증거 무결성

```text
파일: evidence/lab-traffic.pcap
SHA-256: 8070963872a0b5f1bba9ec10363639ff1b8243965918b09a9f121381697a559e
해시 일치: true
PCAP format: 2.4, Ethernet, microseconds
```

구조화된 검증 결과:

- `evidence/pcap-regression.json`
- `evidence/ids-comparison.json`
- `evidence/sigma-validation.json`
- `evidence/case-manifest.json`
- `evidence/incident-timeline.json`

## Elastic Stack

```text
Elasticsearch: 9.4.2
Logstash:      9.4.2
Kibana:        9.4.2
Index:         ids-alerts-2026.08.08
Documents:     90
Dashboard:     network-forensics-overview
```

## 재검증 명령

```powershell
python -m unittest discover -s tests -v
coverage run --branch -m unittest discover -s tests
coverage report -m
docker compose config --quiet
.\scripts\run-comparison.ps1
Invoke-RestMethod http://127.0.0.1:9200/ids-alerts-*/_count
Invoke-RestMethod http://127.0.0.1:5601/api/status
Invoke-RestMethod http://127.0.0.1:5601/api/dashboards/network-forensics-overview
node --check .\scripts\capture-kibana.mjs
```

> 이 기록은 저장소의 단일 로컬 합성 회귀 fixture에 대한 검증 결과이며 운영망 성능·정확도 측정이 아닙니다. 정상 전용 fixture가 분리되기 전까지 recall·precision·FPR을 주장하지 않습니다.
