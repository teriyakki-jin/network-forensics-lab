# 실습 검증 결과

검증일: 2026-09-08 (Asia/Seoul)

## 최종 상태

| 항목 | 결과 |
|---|---|
| Docker 격리망 | `10.77.0.0/24`, `internal: true` |
| Kali → Nginx/CoreDNS/차량 Gateway 트래픽 | 8개 허가 시나리오 성공 |
| PCAP 수집 | 170 packets, 16,984 bytes |
| PCAP SHA-256 | 일치 |
| Snort 3 분석 | 43 alerts |
| Suricata 8 분석 | 43 alerts |
| 교차 탐지 | 8/8 시나리오, 모든 delta 0 |
| Sigma | 8 rules valid |
| paired fixture 평가 | 공격 8 + 정상 8, 5회, 양쪽 엔진 recall 100%·FPR 0% |
| 사건 증거 | 5 artifacts hashed, 86 timeline events |
| Elasticsearch | 86 documents |
| Kibana | `available`, Lens dashboard 7 panels |
| Python test | 40 passed, branch coverage 포함 전체 92% |

## 탐지 결과

| SID | 시나리오 | ATT&CK | Snort | Suricata |
|---|---|---|---:|---:|
| `1000001` | `icmp_echo` | T1018 | 1 | 1 |
| `1000002` | `http_admin_probe` | T1190 | 1 | 1 |
| `1000003` | `tcp_syn_scan` | T1046 | 33 | 33 |
| `1000004` | `brute_force` | T1110 | 1 | 1 |
| `1000005` | `dns_tunneling` | T1071.004 | 4 | 4 |
| `1000006` | `web_exploit` | T1190 | 1 | 1 |
| `1000007` | `doip_unauthorized_diagnostic` | T1692.001 | 1 | 1 |
| `1000008` | `someip_service_discovery` | T0846.003 | 1 | 1 |
| **합계** |  |  | **43** | **43** |

## 증거 무결성

```text
파일: evidence/lab-traffic.pcap
SHA-256: 78cb430a5760aeb276e27b149b2e18017c68aab414155bc2abe31778f64e6530
해시 일치: true
PCAP format: 2.4, Ethernet, microseconds
```

구조화된 검증 결과:

- `evidence/pcap-regression.json`
- `evidence/ids-comparison.json`
- `evidence/sigma-validation.json`
- `evidence/case-manifest.json`
- `evidence/incident-timeline.json`
- `evidence/evaluation/detection-metrics.json`
- `evidence/evaluation/attack-traffic.pcap.sha256`
- `evidence/evaluation/benign-traffic.pcap.sha256`

## Elastic Stack

```text
Elasticsearch: 9.4.2
Logstash:      9.4.2
Kibana:        9.4.2
Index:         ids-alerts-2026.08.08
Documents:     86
Dashboard:     network-forensics-overview
```

## 재검증 명령

```powershell
python -m unittest discover -s tests -v
coverage run --branch -m unittest discover -s tests
coverage report -m
docker compose config --quiet
.\scripts\run-comparison.ps1
.\scripts\run-evaluation.ps1 -UseCommittedFixtures
Invoke-RestMethod http://127.0.0.1:9200/ids-alerts-*/_count
Invoke-RestMethod http://127.0.0.1:5601/api/status
Invoke-RestMethod http://127.0.0.1:5601/api/dashboards/network-forensics-overview
node --check .\scripts\capture-kibana.mjs
```

> recall·precision·FPR은 고유 공격 8개와 정상 8개로 구성된 로컬 paired synthetic fixture를 5회 반복한 결과입니다. 운영망 성능·정확도로 일반화하지 않습니다.
