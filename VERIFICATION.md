# 실습 검증 결과

검증일: 2026-08-08 (Asia/Seoul)

## 최종 상태

| 항목 | 결과 |
|---|---|
| Docker 격리망 | `10.77.0.0/24`, `internal: true` |
| Kali → Nginx/CoreDNS 트래픽 | 6개 허가 시나리오 성공 |
| PCAP 수집 | 159 packets, 16,025 bytes |
| PCAP SHA-256 | 일치 |
| Snort 3 분석 | 45 alerts |
| Suricata 8 분석 | 45 alerts |
| 교차 탐지 | 6/6 시나리오, 모든 delta 0 |
| Sigma | 6 rules valid |
| Elasticsearch | 90 documents |
| Kibana | `available`, Lens dashboard 7 panels |
| Python test | 23 passed, overall coverage 91% |

## 탐지 결과

| SID | 시나리오 | ATT&CK | Snort | Suricata |
|---|---|---|---:|---:|
| `1000001` | `icmp_echo` | T1018 | 4 | 4 |
| `1000002` | `http_admin_probe` | T1190 | 1 | 1 |
| `1000003` | `tcp_syn_scan` | T1046 | 33 | 33 |
| `1000004` | `brute_force` | T1110 | 1 | 1 |
| `1000005` | `dns_tunneling` | T1071.004 | 5 | 5 |
| `1000006` | `web_exploit` | T1190 | 1 | 1 |
| **합계** |  |  | **45** | **45** |

## 증거 무결성

```text
파일: evidence/lab-traffic.pcap
SHA-256: 93160865ac7136c6f609e8c72a4940326e4c0ec22c16b9ab18f3463d09ae82f0
해시 일치: true
PCAP format: 2.4, Ethernet, microseconds
```

구조화된 검증 결과:

- `evidence/pcap-regression.json`
- `evidence/ids-comparison.json`
- `evidence/sigma-validation.json`

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

> 이 기록은 저장소의 로컬 회귀 fixture에 대한 검증 결과이며 운영망 성능·정확도 측정이 아닙니다.
