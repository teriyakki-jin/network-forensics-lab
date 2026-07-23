# 실습 검증 결과

검증일: 2026-07-23 (Asia/Seoul)

## 최종 상태

| 항목 | 결과 |
|---|---|
| Docker 격리망 | `10.77.0.0/24`, `internal: true` |
| Kali → Nginx 트래픽 | 성공 |
| PCAP 수집 | 84패킷, 6,778바이트 |
| PCAP SHA-256 | 일치 |
| Snort 3 분석 | 30건 탐지 |
| Logstash 파이프라인 | 정상 시작 및 적재 완료 |
| Elasticsearch 문서 | 30건 |
| Kibana 상태 | `available` |
| Kibana 데이터 뷰 | `snort-alerts-*` |
| README 화면 캡처 | `assets/kibana-discover.png` |

## 탐지 결과

| SID | 규칙 | 건수 |
|---|---|---:|
| `1000001` | LAB ICMP Echo Request | 3 |
| `1000002` | LAB HTTP Admin Command Probe | 1 |
| `1000003` | LAB TCP SYN Scan | 26 |
| **합계** |  | **30** |

## 증거 무결성

```text
파일: evidence/lab-traffic.pcap
SHA-256: 504c3711f3244644293fc261d7424b3971dbddb2eb8402fcfe2ad1c57877bbdd
해시 일치: True
```

## Elastic Stack

```text
Elasticsearch: 9.4.2
Logstash:      9.4.2
Kibana:        9.4.2
Index:         snort-alerts-2026.07.23
Documents:     30
```

단일 노드 실습 환경에서 인덱스 replica가 배정되지 않아 인덱스 상태가 `yellow`로 표시될 수 있습니다. primary shard와 30개 문서는 정상입니다.

## 검증 명령

```powershell
docker compose config --quiet
docker compose ps
Invoke-RestMethod http://127.0.0.1:9200/snort-alerts-*/_count
Invoke-RestMethod http://127.0.0.1:5601/api/status
```

PowerShell 실행 스크립트 구문, Compose 구성, Snort JSON 30개 행 파싱, PCAP SHA-256 일치를 모두 확인했습니다.
