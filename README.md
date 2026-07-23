# 격리형 네트워크 포렌식 실습망

이 프로젝트는 Docker Desktop에서 다음 흐름을 재현합니다.

```text
Kali (10.77.0.20) -> Nginx 피해 서버 (10.77.0.10)
       | PCAP 수집
       v
Snort 3 오프라인 탐지 -> JSON -> Logstash -> Elasticsearch -> Kibana
```

`lab_net`은 `internal: true`인 격리 네트워크입니다. 테스트 트래픽은 ICMP, HTTP `/admin?cmd=id`, 제한된 1~30번 TCP 포트 SYN 스캔이며 이 실습망 밖으로 전송되지 않습니다.

Elastic JVM 메모리는 Docker Desktop 실습용으로 Elasticsearch 1GB, Logstash 384MB, Kibana 768MB로 제한되어 있습니다.

## 실행

PowerShell에서 다음을 실행합니다.

```powershell
Set-Location 'C:\Users\USER\Documents\Codex\2026-07-23\new-chat\outputs\network-forensics-lab'
powershell -ExecutionPolicy Bypass -File .\scripts\run-lab.ps1
```

Elastic 이미지 다운로드를 뒤로 미루고 PCAP/Snort까지만 검증하려면:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-lab.ps1 -SkipElastic
```

## 생성 결과

- `evidence/lab-traffic.pcap`: 원본 패킷
- `evidence/lab-traffic.pcap.sha256`: SHA-256 해시
- `evidence/nmap-result.txt`: 제한된 포트 스캔 결과
- `alerts/alert_json.txt`: Snort JSON 경보

Kali의 tshark로 PCAP을 확인할 수 있습니다.

```powershell
docker compose exec kali tshark -r /evidence/lab-traffic.pcap -q -z conv,tcp
docker compose exec kali tshark -r /evidence/lab-traffic.pcap -Y 'http.request' -V
```

## Kibana

1. `http://127.0.0.1:5601` 접속
2. Discover에서 Data View 생성
3. 인덱스 패턴: `snort-alerts-*`
4. 시간 필드: `@timestamp`

KQL 예시:

```text
rule.id: "1000001"
```

```text
source.ip: "10.77.0.20" and destination.ip: "10.77.0.10"
```

```text
rule.description: "LAB TCP SYN Scan"
```

## 종료

컨테이너만 종료하고 Elastic 데이터를 보존합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1
```

Elastic 볼륨까지 삭제하려면 명시적으로 다음을 사용합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1 -DeleteElasticData
```

이 구성의 인증 비활성화 설정은 로컬 격리 실습 전용입니다. 운영망에는 그대로 사용하지 마십시오.

## Docker Desktop 복구

Elastic 기동 중 Docker Desktop이 비정상 종료된 뒤 `WSL/Service/CreateInstance/E_FAIL`이 발생하면 관리자 PowerShell에서 다음을 실행하거나 Windows를 재시작하십시오.

```powershell
wsl --shutdown
Restart-Service WslService -Force
Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
```

Docker가 준비되면 `scripts/run-lab.ps1`을 다시 실행합니다. 내려받은 이미지와 Docker 볼륨은 삭제하지 않는 한 유지됩니다.
