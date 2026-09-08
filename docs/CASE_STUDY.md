# 구현 사례: 자동차 Ethernet 네트워크 포렌식 랩

## 시작한 이유

처음에는 Kali에서 트래픽을 만들고 Snort 경보를 Kibana에서 확인하는 정도의 실습이었다. 직접 실행해 보니 경보가 뜬다는 사실만으로는 설명하기 어려운 부분이 많았다. Snort의 판단이 맞는지 비교할 대상이 없었고, PCAP이 바뀌지 않았다는 근거도 부족했다. 규칙을 수정한 뒤 예전 시나리오가 계속 탐지되는지도 사람이 다시 확인해야 했다.

그래서 목표를 도구 설치가 아닌 검증 과정으로 바꿨다. 같은 PCAP을 Snort와 Suricata가 각각 분석하고, 결과를 같은 형식으로 정리한 다음, 원본부터 대시보드까지 다시 만들 수 있는 구조를 잡았다. 차량 네트워크 직무와 연결하기 위해 DoIP와 SOME/IP-SD 트래픽도 추가했다.

## 구성

| 구분 | 구현 내용 |
|---|---|
| 격리망 | Docker 내부망 `10.77.0.0/24`, 고정 IP 사용 |
| 트래픽 생성 | Kali에서 허가된 공격·정상 시나리오 실행 |
| 차량 구간 | DoIP TCP 13400, SOME/IP-SD UDP 30490 시뮬레이터 |
| 증거 수집 | `tcpdump` PCAP, SHA-256, 사건 manifest와 타임라인 |
| 탐지 | Snort 3와 Suricata 8의 오프라인 분석 |
| 데이터 정리 | 두 엔진의 경보를 공통 JSON 형식으로 변환 |
| 표준 연결 | MITRE ATT&CK, ATT&CK for ICS, Sigma 규칙 |
| 조회 | Logstash, Elasticsearch, Kibana Lens |
| 회귀 검사 | Python 테스트와 GitHub Actions |

공격 트래픽은 `internal: true`로 설정한 Docker 네트워크 밖으로 나갈 수 없다. Snort와 Suricata 컨테이너에는 네트워크 인터페이스도 주지 않았다. 캡처가 끝난 PCAP만 읽게 해 분석 중 외부 통신 가능성을 줄이고, 두 엔진의 입력도 같게 만들었다.

```text
Kali 10.77.0.20
  ├─ Nginx 10.77.0.10
  ├─ CoreDNS 10.77.0.53
  └─ Vehicle Gateway 10.77.0.30
          ↓ tcpdump
       동일 PCAP
        ├─ Snort 3
        └─ Suricata 8
              ↓
       정규화 → Elastic → Kibana
```

## 차량 네트워크 시나리오

기존의 ICMP, HTTP 관리 경로 접근, SYN scan, Basic 인증 반복, DNS 터널 형태, SQL injection 형태 요청에 두 가지 차량 Ethernet 시나리오를 더했다.

- DoIP: UDS `WriteDataByIdentifier(0x2E)`가 들어 있는 진단 메시지
- SOME/IP-SD: 허가되지 않은 `FindService` 메시지

실제 ECU나 차량에는 연결하지 않는다. 공개된 프로토콜 구조를 참고해 만든 바이트를 격리된 Gateway 시뮬레이터로 보낸다. 정상 fixture에서는 DoIP `ReadDataByIdentifier(0x22)`와 SOME/IP-SD `OfferService`를 사용해 공격 트래픽과 짝을 맞췄다.

## 서로 다른 IDS 결과 맞추기

Snort와 Suricata는 필드 이름과 시간 형식이 다르다. 두 원본을 바로 Elasticsearch에 넣으면 같은 시나리오도 별개의 데이터처럼 보인다. Python 정규화기에서 다음 필드만 공통 형식으로 만들었다.

```text
@timestamp
engine
scenario
source / destination
network.transport
rule
threat.tactic / threat.technique
```

SID와 ATT&CK 정보는 `detection/rule-catalog.json` 한 곳에서 관리한다. 정규화기는 SID로 catalog를 조회해 두 엔진에 같은 시나리오 이름과 ATT&CK 정보를 붙인다. Basic 인증 헤더처럼 자격 증명이 포함될 수 있는 원문 payload는 결과 JSON에 복사하지 않았다.

## 작업 중 해결한 문제

### Elasticsearch는 실행 중이어도 바로 준비되지 않았다

컨테이너 상태가 `running`으로 바뀐 직후 인덱스 API를 호출하면 연결이 끊길 때가 있었다. JVM과 REST API 초기화가 끝나지 않은 상태였다. 이후 `/_cluster/health?wait_for_status=yellow` 응답을 확인한 뒤 인덱스 작업을 시작하도록 순서를 바꿨다.

### wildcard 인덱스 삭제가 막혔다

Elasticsearch 9에서는 `DELETE /ids-alerts-*` 요청이 안전 설정에 걸렸다. `_cat/indices`로 대상 이름을 먼저 읽고, `ids-alerts-` 접두사를 다시 확인한 뒤 정확한 인덱스만 하나씩 삭제하도록 수정했다. 삭제 범위도 이전보다 분명해졌다.

### ICMP 규칙의 경계값에서 결과가 흔들렸다

정상 ping과 공격 ping을 나누기 위해 ICMP 규칙에 임계치를 넣었는데, 공격 fixture도 임계치와 같은 3회로 설정해 실행 조건에 따라 경보가 달라졌다. 정상은 1회, 공격은 4회로 간격을 벌린 뒤 5회 반복 분석으로 결과가 고정되는지 확인했다.

### 패킷 수를 테스트에 고정하면 정상 변경도 실패했다

초기 테스트에는 예전 PCAP의 패킷 수가 그대로 들어 있었다. 시나리오를 추가하자 정상적인 변경인데도 테스트가 깨졌다. 테스트는 PCAP 구조와 계산된 파일 크기의 일치 여부를 검사하고, 실행별 패킷 수와 해시는 증거 JSON에 남기는 방식으로 역할을 나눴다.

## 확인한 결과

메인 공격 PCAP과 공격·정상 paired fixture를 따로 평가했다.

| 항목 | 결과 |
|---|---:|
| 메인 PCAP | 170 packets, 16,984 bytes |
| Snort / Suricata 경보 | 각각 43건 |
| 양쪽 엔진에서 탐지한 공격 시나리오 | 8 / 8 |
| 시나리오별 두 엔진 경보 수 차이 | 0 |
| paired fixture | 공격 8개 + 정상 8개 |
| 반복 횟수 | 5회 |
| 엔진별 confusion matrix | TP 40, TN 40, FP 0, FN 0 |
| 엔진별 recall / precision / FPR | 100% / 100% / 0% |
| 반복 성공 | Snort 5/5, Suricata 5/5 |
| 자동 테스트 | 40개 통과, branch coverage 포함 92% |

여기서 엔진별 관측값 80개는 서로 다른 시나리오 80개가 아니다. 공격 8개와 정상 8개를 5회 반복한 결과다. 따라서 이 수치는 저장소에 포함된 로컬 합성 fixture의 회귀 결과로만 사용한다. 실제 차량이나 운영망에서 탐지율 100%를 달성했다는 뜻은 아니다.

## 자동 검증

GitHub Actions에서는 Python 테스트만 실행하지 않는다. 커밋된 PCAP의 해시와 구조를 확인하고, Snort와 Suricata 컨테이너로 실제 재분석한다. 공격·정상 fixture도 5회 돌려 recall, precision, FPR과 반복 성공 여부가 기존 결과에서 벗어나지 않는지 검사한다.

이 구조 덕분에 규칙 문법은 맞지만 실제 패킷을 놓치는 변경, SID와 ATT&CK 정보가 어긋나는 변경, 정상 트래픽에서 새 경보가 생기는 변경을 PR 단계에서 확인할 수 있다.

## 남은 한계

- 정상 fixture가 작아 실제 업무 트래픽의 다양성을 대표하지 못한다.
- DoIP와 SOME/IP-SD 메시지는 학습용 합성 데이터이며 ECU 동작을 재현하지 않는다.
- 암호화 트래픽 복호화와 TLS inspection은 다루지 않았다.
- IDS는 저장된 PCAP을 분석하며 인라인 차단 성능은 평가하지 않았다.
- 다음 검증에는 공개 automotive PCAP과 장시간 정상 baseline이 필요하다.
