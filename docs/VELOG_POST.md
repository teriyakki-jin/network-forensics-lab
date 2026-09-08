<!--
Velog 제목: Snort 경보 확인에서 끝내지 않고, 자동차 Ethernet 포렌식 랩까지 만든 과정
Velog 태그: 네트워크보안, 디지털포렌식, Snort, Suricata, Wireshark, ELK, Docker, MITREATTACK
-->

# Snort 경보 확인에서 끝내지 않고, 자동차 Ethernet 포렌식 랩까지 만든 과정

처음 만든 버전은 단순했다. Docker 격리망에서 Kali로 트래픽을 보내고 Snort 경보를 Kibana에서 확인했다. ICMP, HTTP 관리 경로 접근, SYN scan까지는 잘 잡혔다.

문제는 그다음이었다. “경보가 떴다”는 화면만으로는 다음 질문에 답하기 어려웠다.

- Snort 한 개의 판단을 어떻게 검증할 것인가?
- 분석에 사용한 PCAP이 바뀌지 않았다는 근거는 무엇인가?
- 규칙을 수정한 뒤 기존 탐지가 깨지지 않았는가?
- 정상 트래픽에서도 같은 규칙이 울리지 않는가?
- 차량 보안 직무와 연결되는 부분은 어디인가?

이 질문을 하나씩 해결하면서 지금의 자동차 Ethernet 네트워크 포렌식 랩으로 확장했다.

## 현재 결과

| 항목 | 결과 |
|---|---:|
| 고유 공격 시나리오 | 8개 |
| 고유 정상 시나리오 | 8개 |
| 반복 평가 | 5회 |
| 메인 PCAP | 170 packets, 16,984 bytes |
| Snort / Suricata 경보 | 각각 43건 |
| 양쪽 IDS에서 탐지된 공격 시나리오 | 8 / 8 |
| 엔진별 TP / TN / FP / FN | 40 / 40 / 0 / 0 |
| 엔진별 recall / precision / FPR | 100% / 100% / 0% |
| 반복 성공 | 각각 5/5 |
| 자동 테스트 | 40개 통과, branch coverage 포함 92% |

수치의 범위는 분명히 해야 한다. 엔진별 관측값 80개는 공격 8개와 정상 8개를 5회 반복한 값이다. 서로 다른 시나리오가 80개라는 뜻이 아니다. 실제 운영망의 탐지 정확도도 아니며, 저장소에 포함된 합성 fixture의 회귀 결과다.

![Kibana Lens 대시보드](../assets/kibana-lens-dashboard.png)

## 1. 트래픽이 밖으로 나가지 않게 했다

보안 실습에서는 기능보다 범위를 먼저 고정해야 한다고 생각했다. 공격용 네트워크를 `10.77.0.0/24`로 정하고 Docker의 외부 라우팅을 막았다.

```yaml
networks:
  lab_net:
    internal: true
    ipam:
      config:
        - subnet: 10.77.0.0/24
```

각 컨테이너의 주소도 고정했다.

- Kali: `10.77.0.20`
- Nginx: `10.77.0.10`
- 차량 Gateway: `10.77.0.30`
- CoreDNS: `10.77.0.53`

Snort와 Suricata는 라이브 네트워크를 보지 않는다. `network_mode: none`으로 실행하고 캡처가 끝난 PCAP만 읽는다. 덕분에 분석 중 외부 통신이 발생하지 않고, 두 엔진이 정확히 같은 입력을 사용한다.

## 2. 차량 Ethernet 트래픽을 추가했다

기존 6개 시나리오에 DoIP와 SOME/IP-SD를 더했다.

```text
icmp_echo
http_admin_probe
tcp_syn_scan
brute_force
dns_tunneling
web_exploit
doip_unauthorized_diagnostic
someip_service_discovery
```

DoIP 시나리오는 UDS `WriteDataByIdentifier(0x2E)`를 담은 진단 메시지를 TCP 13400으로 보낸다. SOME/IP-SD 시나리오는 UDP 30490으로 `FindService` entry를 보낸다.

실제 차량이나 ECU에는 연결하지 않았다. Python으로 만든 Gateway 시뮬레이터가 격리망 안에서 메시지만 받는다. Wireshark에서는 다음 필터로 확인할 수 있다.

```text
doip || tcp.port == 13400
```

```text
someip || udp.port == 30490
```

SOME/IP가 자동으로 해석되지 않으면 UDP 30490을 SOME/IP 디코더에 지정하면 된다.

## 3. 두 IDS의 결과를 같은 형식으로 맞췄다

Snort와 Suricata는 같은 패킷을 보고도 서로 다른 JSON을 만든다. 시간, 출발지와 목적지, SID 필드 위치가 모두 다르다. 그래서 Python으로 필요한 필드만 뽑아 공통 형식으로 변환했다.

```json
{
  "@timestamp": "2026-09-08T10:59:01.000000Z",
  "engine": "snort",
  "scenario": "dns_tunneling",
  "source": { "ip": "10.77.0.20" },
  "destination": { "ip": "10.77.0.53", "port": 53 },
  "threat": {
    "technique": { "id": "T1071.004", "name": "DNS" }
  }
}
```

시나리오 이름과 ATT&CK 정보는 `detection/rule-catalog.json`에서 가져온다. Snort와 Suricata 규칙에 같은 정보를 반복해서 적으면 수정할 때 어긋날 수 있기 때문이다.

정규화 과정에서 payload 전체를 복사하지 않은 것도 의도한 선택이다. HTTP Basic 인증 헤더처럼 자격 증명이 섞일 수 있는 데이터는 제외하고, 분석에 필요한 주소·포트·규칙 정보만 남겼다.

## 4. PCAP을 증거로 다뤘다

PCAP에는 SHA-256 checksum을 붙였다. 해시만 맞는다고 끝내지 않고 작은 검사기를 만들어 다음 항목도 확인한다.

- PCAP magic number와 byte order
- format version과 link type
- packet header가 끝까지 정상적으로 이어지는지
- 파일 크기와 packet byte 계산값이 맞는지
- 잘린 packet이 없는지

```powershell
python -m forensics.cli verify-fixture `
  --pcap evidence/lab-traffic.pcap `
  --checksum evidence/lab-traffic.pcap.sha256
```

현재 메인 PCAP의 SHA-256은 다음과 같다.

```text
78cb430a5760aeb276e27b149b2e18017c68aab414155bc2abe31778f64e6530
```

분석이 끝나면 `case-manifest.json`에 사건번호, 수집 시각, 센서 ID, 도구 버전과 주요 결과 파일의 해시를 기록한다. `incident-timeline.json`에는 Snort와 Suricata 경보를 시간순으로 정리한다.

## 5. 공격 PCAP만으로는 부족했다

초기 결과는 공격 시나리오 8개를 모두 탐지했다는 것뿐이었다. 이 상태에서는 recall은 이야기할 수 있어도 정상 트래픽의 오탐 여부는 알 수 없다.

그래서 같은 8개 규칙마다 정상 동작을 하나씩 짝지었다.

- ICMP burst ↔ 단일 ping
- SYN scan ↔ 80번 포트 1회 연결
- Basic 인증 반복 ↔ 승인된 인증 1회
- 긴 DNS 터널 형태 ↔ 일반 DNS 질의
- UDS 쓰기 명령 ↔ UDS 읽기 명령
- SOME/IP-SD FindService ↔ OfferService

공격과 정상 PCAP을 각각 만든 뒤 두 엔진에서 5회씩 분석했다.

```powershell
.\scripts\run-evaluation.ps1
```

커밋된 PCAP만 다시 분석할 때는 다음 옵션을 사용한다.

```powershell
.\scripts\run-evaluation.ps1 -UseCommittedFixtures
```

결과는 두 엔진 모두 TP 40, TN 40, FP 0, FN 0이었다. 반복도 각각 5/5로 같았다. 이 값은 정상 fixture가 작은 로컬 실험 결과이므로 자기소개서에는 다음 정도로 표현하는 것이 정확하다.

> 공격·정상 16개 합성 시나리오를 5회 반복한 로컬 회귀에서 Snort와 Suricata 모두 recall 100%, FPR 0%, 반복 성공 5/5를 기록했다.

## 6. 실제로 막혔던 부분

### Elasticsearch 준비 시점

`docker compose up -d` 직후 인덱스 API를 호출하면 간헐적으로 연결이 끊겼다. 컨테이너는 실행 중이지만 Elasticsearch REST API가 아직 준비되지 않은 상태였다. `/_cluster/health`가 yellow 이상이 될 때까지 기다린 다음 인덱스 작업을 시작하도록 바꿨다.

### Elasticsearch 9의 wildcard 삭제

기존의 `DELETE /ids-alerts-*` 요청은 안전 설정 때문에 실패했다. `_cat/indices`로 실제 인덱스 이름을 가져오고, 접두사를 다시 확인한 뒤 정확한 이름만 삭제하게 수정했다.

### ICMP 탐지 임계치

정상 ping을 제외하려고 3회 임계치를 넣었지만 공격도 정확히 3회로 만들었다. 실행 조건에 따라 탐지가 달라지는 문제가 생겼다. 정상은 1회, 공격은 4회로 바꾼 뒤 5회 반복 결과가 같은지 확인했다. 작은 경계값 하나가 회귀 결과 전체를 흔들 수 있다는 점을 직접 확인한 부분이었다.

## 7. 대시보드도 코드로 만들었다

Kibana 화면을 손으로 만들면 다른 환경에서 그대로 재현하기 어렵다. 데이터 뷰와 Lens 패널을 PowerShell 스크립트에서 생성하도록 바꿨다. 같은 ID로 갱신하기 때문에 스크립트를 여러 번 실행해도 대시보드가 중복되지 않는다.

현재 화면에서는 전체 경보 수, 탐지 시나리오 수, 엔진별 비율, ATT&CK technique 분포, 출발지와 목적지를 한 번에 볼 수 있다. Headless Chrome 캡처도 자동화해 README 이미지와 실제 화면이 어긋나지 않게 했다.

## 8. CI에서 실제 IDS를 실행한다

규칙 파일이 문법 검사를 통과해도 실제 PCAP에서 경보가 나오지 않을 수 있다. GitHub Actions에서 Snort와 Suricata 컨테이너를 직접 실행하도록 한 이유다.

```text
Python test와 branch coverage
  → PCAP hash와 구조 검사
  → Sigma 규칙 검사
  → Snort·Suricata 메인 PCAP 분석
  → 공격·정상 paired fixture 5회 분석
  → 결과 수치와 스크립트 구문 확인
```

규칙을 바꿔 공격을 놓치거나 정상 트래픽에서 새 경보가 발생하면 PR 검사가 실패한다.

## 실행 방법

```powershell
git clone https://github.com/teriyakki-jin/network-forensics-lab.git
Set-Location .\network-forensics-lab
.\scripts\run-lab.ps1
```

Elastic Stack 없이 PCAP과 IDS만 확인하려면:

```powershell
.\scripts\run-lab.ps1 -SkipElastic
```

실습 종료:

```powershell
docker compose down -v --remove-orphans
```

## 마무리

이번 작업에서 가장 오래 걸린 부분은 도구 설치가 아니었다. 같은 입력을 두 엔진에 넣고, 결과를 비교할 기준을 정하고, 정상 트래픽까지 포함해 반복 가능한 수치로 만드는 일이었다.

아직 실제 차량 로그나 장시간 정상 트래픽을 사용한 것은 아니다. 그래도 테스트 범위와 한계를 함께 기록했기 때문에 무엇을 확인했고 무엇을 확인하지 못했는지는 분명해졌다. 다음에는 공개 automotive PCAP을 추가해 합성 fixture 밖에서도 규칙이 유지되는지 확인할 계획이다.

GitHub: https://github.com/teriyakki-jin/network-forensics-lab
