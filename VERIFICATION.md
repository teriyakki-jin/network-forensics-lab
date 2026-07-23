# 실습 검증 결과

검증일: 2026-07-23 (Asia/Seoul)

## 완료된 검증

- Docker 격리망 `10.77.0.0/24` 생성
- Kali `10.77.0.20`에서 Nginx `10.77.0.10`으로 실습 트래픽 생성
- tcpdump/Wireshark 호환 PCAP 82패킷 수집
- PCAP SHA-256 일치 확인
- Snort 3 JSON 경보 30건 생성
- PowerShell 실행 스크립트 구문 검사 통과
- Elasticsearch 9.4.2 클러스터가 한 차례 `GREEN/healthy` 상태로 기동됨
- Logstash 9.4.2가 Elasticsearch에 연결되고 파이프라인이 시작됨
- Kibana 9.4.2 컨테이너 기동 및 localhost 포트 게시 설정 확인

## 탐지 결과

| SID | 규칙 | 건수 |
|---|---|---:|
| 1000001 | LAB ICMP Echo Request | 3 |
| 1000002 | LAB HTTP Admin Command Probe | 1 |
| 1000003 | LAB TCP SYN Scan | 26 |
| 합계 |  | 30 |

PCAP SHA-256:

```text
1e9c38b493f2ef1818b11c6e9c1ccd944bbb72ab08af0d78d7169cfb8ef8b415
```

## 남은 검증

최종 Elasticsearch 문서 수와 Kibana 화면 접근은 Docker Desktop 4.25.1의 WSL 백엔드가 `WSL/Service/CreateInstance/E_FAIL`로 중단되어 완료하지 못했습니다. Windows 또는 관리자 권한의 WSL 서비스 재시작 후 `scripts/run-lab.ps1`을 다시 실행하면 자동 검증됩니다.
