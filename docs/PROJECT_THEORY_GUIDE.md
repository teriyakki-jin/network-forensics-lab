# 자동차 Ethernet 네트워크 포렌식 랩 이론 정리

이 문서는 프로젝트를 실행하는 방법보다 “왜 이렇게 구성했는가”를 이해하기 위한 학습 노트다. 면접에서는 도구 이름을 나열하는 것보다 패킷이 만들어지고, 수집되고, 탐지되고, 증거로 남는 과정을 설명할 수 있어야 한다.

## 1. 프로젝트 전체 흐름

```text
Kali에서 테스트 트래픽 생성
  → tcpdump로 원본 PCAP 수집
  → SHA-256으로 무결성 확인
  → Snort와 Suricata가 같은 PCAP 분석
  → 엔진별 경보를 공통 JSON으로 변환
  → ATT&CK·Sigma 정보 연결
  → Logstash → Elasticsearch → Kibana
  → 사건 manifest와 타임라인 생성
  → CI에서 같은 분석을 반복
```

핵심은 같은 원본을 두 탐지 엔진에 넣는 것이다. 입력이 다르면 경보 차이가 엔진 때문인지 트래픽 때문인지 구분하기 어렵다. 동일 PCAP을 사용하면 규칙과 엔진의 차이에 집중할 수 있다.

## 2. 네트워크에서 먼저 알아야 할 것

### OSI 계층과 이 프로젝트의 위치

| 계층 | 프로젝트에서 보는 정보 | 예시 |
|---|---|---|
| L2 데이터 링크 | Ethernet frame, MAC 주소 | PCAP의 link type |
| L3 네트워크 | IPv4, ICMP, 출발지·목적지 IP | `10.77.0.20 → 10.77.0.10` |
| L4 전송 | TCP/UDP, 포트, TCP flag | SYN scan, TCP 13400, UDP 30490 |
| L7 응용 | HTTP, DNS, DoIP, SOME/IP-SD | URI, DNS query, UDS service byte |

IDS 규칙은 한 계층만 보는 것이 아니다. SYN scan은 주로 L3·L4 특징을 사용하고, SQL injection 형태 요청은 HTTP URI까지 확인한다. DoIP 규칙은 TCP 연결 안의 응용 계층 byte를 검사한다.

### TCP와 UDP 차이

TCP는 연결형 프로토콜이다. 일반적으로 SYN → SYN/ACK → ACK의 3-way handshake 후 데이터를 보낸다. 순서, 재전송, 흐름 상태를 관리하므로 IDS에서 `established`, `to_server`, stream reassembly 같은 조건을 사용할 수 있다.

UDP는 연결 설정 없이 datagram을 보낸다. 빠르고 단순하지만 전달·순서를 보장하지 않는다. DNS와 SOME/IP-SD처럼 짧은 요청이나 discovery에 자주 사용한다. IDS는 한 UDP packet의 header와 payload를 직접 검사하는 경우가 많다.

### TCP SYN scan

SYN scan은 여러 포트에 SYN을 보내고 응답으로 포트 상태를 추정한다.

- SYN/ACK: 포트가 열려 있을 가능성
- RST: 포트가 닫혀 있을 가능성
- 응답 없음 또는 ICMP error: 방화벽에서 차단됐을 가능성

한 번의 SYN은 정상 연결에서도 발생한다. 그래서 규칙은 SYN 자체가 아니라 일정 시간 안에 같은 출발지에서 여러 SYN이 발생하는지를 본다. 이 프로젝트의 `detection_filter`도 이 원리를 사용한다.

### DNS 터널링 징후

DNS 터널링은 데이터를 subdomain에 인코딩해 DNS 질의로 보내는 방식이다. 다음 특징이 단서가 될 수 있다.

- 비정상적으로 긴 label
- 무작위성이 높은 문자열
- 같은 도메인으로 많은 query 발생
- TXT 등 평소 적게 쓰는 record type 증가
- 일정한 주기의 beacon 형태

긴 query 하나만으로 터널링을 확정할 수는 없다. CDN, 보안 제품, 추적 도메인에서도 긴 이름이 나타난다. 실제 환경에서는 길이, 빈도, entropy, 도메인 평판과 단말 행위를 함께 봐야 한다.

## 3. PCAP과 패킷 포렌식

### PCAP이 담는 정보

PCAP 파일은 global header와 packet record의 연속으로 구성된다.

```text
Global Header
  - magic number
  - version
  - timestamp precision
  - snap length
  - link type

Packet Record 1
  - timestamp
  - captured length
  - original length
  - captured bytes
...
```

`captured length`가 `original length`보다 작으면 snap length 때문에 packet 일부만 저장됐을 수 있다. 파일 끝에서 packet data가 부족하면 캡처 파일이 잘렸거나 손상됐을 가능성이 있다.

### BPF capture filter와 Wireshark display filter

두 필터는 적용 시점이 다르다.

- capture filter: 수집할 packet 자체를 제한한다. 예: `host 10.77.0.30`
- display filter: 이미 수집된 packet 중 화면에 표시할 것만 고른다. 예: `doip || tcp.port == 13400`

포렌식 수집에서는 capture filter를 너무 좁게 잡으면 나중에 필요한 주변 맥락을 잃을 수 있다. 저장 공간과 개인정보 범위를 고려하되, 분석에 필요한 전후 packet을 확보해야 한다.

### Wireshark에서 확인할 순서

1. `Statistics → Protocol Hierarchy`에서 전체 프로토콜 비율 확인
2. `Statistics → Conversations`에서 통신 주체와 byte 수 확인
3. 시간순으로 SYN, DNS, HTTP, DoIP, SOME/IP-SD 확인
4. `Follow TCP Stream`으로 TCP 요청과 응답 흐름 확인
5. IDS 경보 시각과 PCAP packet 시각 대조

대표 display filter:

```text
icmp && ip.src == 10.77.0.20
tcp.flags.syn == 1 && tcp.flags.ack == 0
dns && ip.src == 10.77.0.20
http.request.uri contains "/admin"
doip || tcp.port == 13400
someip || udp.port == 30490
```

### 원본과 파생 증거

- 원본 증거: 처음 수집한 PCAP
- 파생 증거: IDS 경보, 정규화 JSON, 타임라인, 화면 캡처

분석 과정에서 원본 PCAP을 수정하지 않는다. 분석 도구가 만든 결과는 별도 파일로 보관하고, 어떤 원본에서 만들어졌는지 manifest로 연결한다.

## 4. SHA-256과 증거 무결성

SHA-256은 임의 길이 입력을 256-bit 값으로 바꾸는 해시 함수다. 같은 파일은 같은 해시를 만들며, 한 bit만 달라져도 결과가 크게 바뀐다.

해시가 증명하는 것은 파일 내용이 기준 시점 이후 바뀌지 않았다는 점이다. 해시만으로 다음 사실까지 증명되지는 않는다.

- 누가 파일을 수집했는가
- 수집 당시 시스템 시간이 정확했는가
- 수집 전에 이미 조작된 데이터인가
- 수집 절차가 적법했는가

그래서 사건번호, 수집자 또는 센서 ID, UTC 수집 시각, 도구 버전, 파일 크기와 해시를 함께 기록한다. 이를 chain of custody의 기초 정보로 볼 수 있다.

## 5. Snort와 Suricata

### 공통점

두 도구 모두 network IDS/IPS로 사용할 수 있으며 header, flow, payload pattern, 빈도 조건으로 규칙을 작성한다. 이 프로젝트에서는 IPS 차단이 아닌 저장된 PCAP의 오프라인 탐지에 사용한다.

### 차이점

| 항목 | Snort 3 | Suricata 8 |
|---|---|---|
| 관리 주체 | Cisco Talos | OISF |
| 출력 | alert_json 등 | EVE JSON 중심 |
| 처리 구조 | Snort 3 모듈 구조 | 다중 thread 처리에 강점 |
| 응용 계층 키워드 | Snort 문법 사용 | HTTP·DNS 등 protocol-aware keyword가 풍부 |

두 엔진의 성능 우열을 이 작은 PCAP으로 판단할 수는 없다. 여기서는 같은 시나리오를 두 엔진이 모두 탐지하는지와 결과 형식 차이를 다루는 것이 목적이다.

### 규칙의 기본 구조

```text
action protocol source_ip source_port direction destination_ip destination_port
(options)
```

예시 개념:

```text
alert tcp any any -> 10.77.0.30 13400
(msg:"..."; flow:to_server,established; content:"..."; sid:1000007; rev:1;)
```

중요 옵션:

- `flow`: 연결 방향과 상태 제한
- `flags:S`: TCP SYN flag 확인
- `content`: payload byte 또는 문자열 확인
- `offset`, `depth`: payload 앞부분의 검사 위치 제한
- `distance`, `within`: 앞 content 이후 상대 위치 제한
- `detection_filter`: 같은 주체의 반복 횟수와 시간 조건
- `sid`: 규칙 식별자
- `rev`: 규칙 개정 번호

### threshold를 쓰는 이유

단일 ping, 한 번의 인증, 한 포트 연결은 정상일 수 있다. 짧은 시간에 반복될 때 의미가 달라진다. threshold는 정상 동작 하나를 공격으로 분류하는 일을 줄이는 데 도움이 된다.

다만 임계치가 너무 낮으면 오탐이 늘고, 너무 높으면 느린 공격을 놓친다. 이 프로젝트에서 공격 ping을 4회, 정상 ping을 1회로 나눈 것도 규칙 경계값을 안정적으로 검증하기 위해서다.

## 6. DoIP와 UDS

### DoIP란

DoIP(Diagnostics over Internet Protocol)는 차량 진단 메시지를 IP 네트워크로 전달하는 프로토콜이다. 일반적으로 TCP/UDP 13400을 사용한다. 기존 CAN 기반 진단을 Ethernet 환경으로 연결하는 역할을 한다.

DoIP header에서 주로 확인할 값:

- protocol version
- inverse protocol version
- payload type
- payload length

이 프로젝트의 공격 fixture는 DoIP diagnostic message payload 안에서 UDS service byte를 확인한다.

### UDS란

UDS(Unified Diagnostic Services)는 ECU 진단에 쓰는 서비스 집합이다. 대표적인 service ID는 다음과 같다.

| SID | 이름 | 용도 |
|---:|---|---|
| `0x10` | DiagnosticSessionControl | 진단 session 변경 |
| `0x22` | ReadDataByIdentifier | 식별값 읽기 |
| `0x27` | SecurityAccess | 보안 접근 challenge/response |
| `0x2E` | WriteDataByIdentifier | 식별값 쓰기 |
| `0x31` | RoutineControl | ECU routine 실행 |

`0x2E` 자체가 항상 공격은 아니다. 승인된 진단 장비가 정비 과정에서 정상적으로 사용할 수 있다. 실제 탐지에서는 출발지 identity, 차량 상태, 진단 session, SecurityAccess 성공 여부, 허용 시간과 대상 ECU를 함께 봐야 한다.

이 랩에서는 범위를 단순화해 `0x2E`를 공격 fixture, `0x22`를 paired 정상 fixture로 사용한다.

## 7. SOME/IP와 SOME/IP-SD

SOME/IP는 차량 Ethernet에서 서비스 지향 통신을 구현할 때 사용하는 프로토콜이다. Service ID, Method ID, Client ID, Session ID 등의 값으로 요청·응답과 event를 구분한다.

SOME/IP-SD(Service Discovery)는 서비스 위치와 사용 가능 여부를 알리는 역할을 한다. 일반적으로 UDP 30490과 multicast를 사용한다.

대표 entry type:

- `FindService`: 필요한 서비스를 찾음
- `OfferService`: 제공 가능한 서비스를 알림
- `SubscribeEventgroup`: event group 구독 요청
- `SubscribeEventgroupAck`: 구독 승인

FindService도 정상 차량에서 필요한 기능이다. 무조건 공격으로 보면 안 된다. 예상하지 않은 단말이 반복적으로 전체 서비스를 찾거나, 정해진 통신 matrix를 벗어난 discovery를 수행할 때 의미가 커진다. 실제 환경에서는 source ECU identity, service allowlist, 차량 상태, 빈도를 함께 확인해야 한다.

## 8. ATT&CK과 ATT&CK for ICS

MITRE ATT&CK은 공격 행위를 tactic과 technique으로 정리한 지식 체계다.

- tactic: 공격자가 달성하려는 목적. 예: Discovery, Credential Access
- technique: 목적을 달성하는 구체적 방법. 예: Network Service Discovery

이 프로젝트의 예:

| 시나리오 | 매핑 |
|---|---|
| SYN scan | Enterprise T1046 Network Service Discovery |
| Basic 인증 반복 | Enterprise T1110 Brute Force |
| DNS 터널 형태 | Enterprise T1071.004 DNS |
| DoIP 쓰기 명령 | ICS T1692.001 Unauthorized Command Message |
| SOME/IP-SD 탐색 | ICS T0846.003 Multicast Discovery |

ATT&CK 매핑은 탐지 의도를 같은 언어로 설명하는 데 유용하다. 하지만 technique ID를 붙였다고 특정 규정 준수나 공격 확정이 되는 것은 아니다.

## 9. Sigma 규칙

Sigma는 로그 탐지 조건을 도구 중립적인 YAML 형식으로 표현하기 위한 규칙 형식이다. SIEM마다 query 문법이 달라도 탐지 의도를 공통 문서로 남길 수 있다.

기본 구성:

```yaml
title: 탐지 이름
status: test
logsource:
  category: network_detection
detection:
  selection:
    scenario: dns_tunneling
  condition: selection
tags:
  - attack.t1071.004
level: high
```

이 프로젝트의 Sigma는 정규화된 `scenario` 값을 기준으로 한다. 완전한 Sigma backend나 SIEM 변환기를 구현한 것은 아니며, 탐지 의도와 ATT&CK 연결이 규칙 변경 중 사라지지 않는지 검사하는 용도다.

## 10. Logstash, Elasticsearch, Kibana

### Logstash

파일에서 JSON 경보를 읽고 필요한 변환을 거쳐 Elasticsearch로 보낸다. input → filter → output 파이프라인으로 생각하면 된다.

### Elasticsearch

JSON document를 index에 저장하고 검색·집계를 수행한다. 이 프로젝트에서는 `ids-alerts-*` index에 정규화 경보를 저장한다.

분석에서 자주 쓰는 집계:

- 전체 경보 수
- `scenario`의 고유 개수
- 엔진별 경보 비율
- ATT&CK technique별 경보 수
- 출발지와 목적지 조합

### Kibana

Elasticsearch 데이터를 검색하고 시각화한다. Discover는 개별 event 확인, Lens dashboard는 집계와 비교에 사용한다. 프로젝트에서는 수동 화면 대신 API로 dashboard를 생성해 같은 구성을 다시 만들 수 있게 했다.

## 11. 탐지 평가 지표

### Confusion matrix

| 구분 | 뜻 |
|---|---|
| TP | 공격을 공격으로 탐지 |
| FN | 공격을 놓침 |
| FP | 정상을 공격으로 잘못 탐지 |
| TN | 정상을 정상으로 처리 |

### Recall

```text
Recall = TP / (TP + FN)
```

실제 공격 중 탐지한 비율이다. FN이 늘면 recall이 낮아진다.

### Precision

```text
Precision = TP / (TP + FP)
```

경보 중 실제 공격의 비율이다. FP가 많으면 분석가가 불필요한 경보를 처리해야 하므로 precision이 낮아진다.

### False Positive Rate

```text
FPR = FP / (FP + TN)
```

정상 중 공격으로 잘못 분류한 비율이다.

### 이 프로젝트 결과를 읽는 법

고유 공격 8개와 정상 8개를 5회 반복했으므로 엔진 하나당 관측값은 80개다.

```text
TP 40, FN 0 → Recall 100%
TP 40, FP 0 → Precision 100%
FP 0, TN 40 → FPR 0%
```

이 결과는 fixture 안에서 규칙이 의도대로 동작했다는 뜻이다. 표본이 작고 합성 데이터이므로 “운영 환경 탐지 정확도 100%”라고 표현하면 안 된다.

## 12. 반복성과 재현성

- 반복성(repeatability): 같은 환경·입력·방법으로 다시 실행했을 때 같은 결과가 나오는가
- 재현성(reproducibility): 다른 환경에서도 설명된 절차로 비슷한 결과를 만들 수 있는가

동일 PCAP을 5회 분석한 것은 반복성 검사에 가깝다. Docker 이미지 digest, 의존성 버전, PCAP checksum, 스크립트와 CI는 다른 환경에서 재현할 가능성을 높이지만 모든 OS와 하드웨어에서 동일함을 증명하지는 않는다.

## 13. Docker 격리의 의미와 한계

`internal: true`는 Docker 네트워크의 외부 라우팅을 막는다. `network_mode: none`은 컨테이너의 네트워크 연결 자체를 없앤다. 고정 사설 IP는 실습 대상 범위를 명시하고 규칙을 단순하게 만든다.

하지만 컨테이너가 가상머신과 같은 완전한 보안 경계는 아니다. Docker daemon 권한, host volume, Linux capability 설정이 잘못되면 host에 영향을 줄 수 있다. 그래서 다음 원칙이 필요하다.

- 필요한 volume만 mount
- 규칙과 PCAP은 가능한 read-only mount
- 불필요한 privileged mode 금지
- 필요한 capability만 부여
- 관리 포트는 localhost에만 bind
- 실제 공격 대상이나 외부 주소를 script에 넣지 않기

## 14. CI가 필요한 이유

탐지 규칙은 일반 코드와 다르게 문법이 맞아도 원하는 packet을 잡지 못할 수 있다. 반대로 공격은 잡지만 정상 packet에서도 울릴 수 있다.

이 프로젝트의 CI는 다음을 확인한다.

1. Python 단위·CLI·저장소 계약 테스트
2. branch coverage 80% 이상
3. PCAP SHA-256과 파일 구조
4. Sigma 필수 필드와 ATT&CK tag
5. Snort·Suricata 메인 PCAP 재분석
6. 공격·정상 paired fixture 5회 평가
7. Compose와 shell·PowerShell 구문

즉, “규칙 파일이 존재한다”가 아니라 “커밋된 packet에서 탐지 결과가 유지된다”를 검사한다.

## 15. 면접에서 설명할 때

### 30초 설명

> Docker 격리망에서 기업·차량 Ethernet 공격과 정상 트래픽을 생성하고, 같은 PCAP을 Snort와 Suricata로 교차 분석하는 프로젝트입니다. DoIP와 SOME/IP-SD 시나리오를 포함했고, PCAP 해시부터 사건 타임라인, ATT&CK·Sigma 매핑, Kibana 시각화와 CI 회귀 검사까지 연결했습니다. 공격 8개와 정상 8개를 5회 반복한 로컬 fixture에서 두 엔진 모두 recall 100%, FPR 0%, 반복 성공 5/5를 기록했습니다.

### “왜 IDS를 두 개 사용했나?”

같은 PCAP에 대해 두 엔진의 탐지 여부와 경보 수를 비교하기 위해서다. 단일 엔진 결과를 그대로 신뢰하기보다 입력을 통제한 상태에서 교차 확인할 수 있다. 다만 두 엔진이 같은 signature 개념을 사용하므로 완전히 독립적인 검증이라고 과장하지 않는다.

### “FPR 0%면 오탐이 없다는 뜻인가?”

아니다. 준비한 정상 fixture 8개를 5회 실행했을 때 FP가 없었다는 뜻이다. 실제 운영망은 protocol, 장비, 사용자 행위가 훨씬 다양하므로 장시간 정상 traffic과 공개 dataset으로 추가 검증해야 한다.

### “DoIP 0x2E는 모두 공격인가?”

아니다. 승인된 진단 장비가 정상 정비 과정에서 사용할 수 있다. 실제 환경에서는 진단 장비 identity, SecurityAccess, 차량 상태, 허용 시간과 대상 ECU를 함께 판단해야 한다. 랩에서는 공격과 정상 fixture를 분리하기 위해 단순화한 조건이다.

### “가장 의미 있었던 문제 해결은?”

ICMP 탐지 임계치와 공격 packet 수가 같아 결과가 흔들린 문제다. 정상 1회와 공격 4회로 경계를 분리하고 두 엔진에서 5회 반복해 결과를 확인했다. 규칙 문법 검사를 넘어 실제 packet 기반 회귀가 필요한 이유를 보여 준 사례다.

### “다음 단계는?”

공개 automotive PCAP과 장시간 정상 traffic을 추가해 합성 데이터 밖에서 규칙을 검증하고, p50/p95 처리 지연과 packet loss도 측정할 수 있다. 차량 통신 matrix와 ECU identity를 적용하면 단순 byte pattern보다 맥락 기반 탐지로 발전시킬 수 있다.

## 16. 꼭 기억할 핵심

1. 경보 개수는 정확도가 아니다.
2. recall을 말하려면 공격 ground truth가 필요하다.
3. precision과 FPR을 말하려면 정상 ground truth가 필요하다.
4. 동일 PCAP은 두 엔진 비교에서 입력 차이를 제거한다.
5. SHA-256은 무결성을 확인하지만 수집 절차 전체를 증명하지는 않는다.
6. DoIP `0x2E`와 SOME/IP-SD FindService는 맥락 없이 공격으로 단정할 수 없다.
7. ATT&CK은 행위 분류 체계이지 탐지 성공이나 규정 준수 인증이 아니다.
8. 오프라인 IDS 평가는 인라인 IPS 차단 성능과 다르다.
9. Docker 격리는 설정에 따라 달라지며 host 권한까지 자동으로 안전하게 만들지는 않는다.
10. 이 프로젝트의 100% 수치는 로컬 합성 fixture 범위에서만 사용한다.

## 17. 이론과 프로젝트 파일 연결

이론만 외우기보다 실제 구현 파일을 같이 보면 설명하기 쉽다.

| 공부할 내용 | 확인할 파일 | 직접 확인할 부분 |
|---|---|---|
| Docker 네트워크 격리 | `compose.yaml` | `internal: true`, 고정 IP, `network_mode: none` |
| 공격·정상 트래픽 | `kali/generate-traffic.sh` | `attack`, `benign` 분기와 목적지 제한 |
| Snort 탐지 문법 | `snort/local.rules` | `content`, `flags`, `detection_filter`, SID |
| Suricata 탐지 문법 | `suricata/local.rules` | HTTP·DNS 응용 계층 keyword와 flow 조건 |
| DoIP·SOME/IP 수신 | `vehicle-gateway/server.py` | TCP 13400과 UDP 30490 처리 |
| 규칙 메타데이터 | `detection/rule-catalog.json` | scenario, SID, ATT&CK mapping |
| Sigma | `detection/sigma/*.yml` | logsource, detection, tag, level |
| 정규화 | `forensics/pipeline.py` | 엔진별 필드를 공통 구조로 변환하는 과정 |
| 평가 지표 | `forensics/incident.py` | confusion matrix와 recall·precision·FPR 계산 |
| ground truth | `evaluation/ground-truth.json` | 같은 scenario의 공격·정상 pair |
| 반복 평가 | `scripts/run-evaluation.ps1` | fixture 캡처, 5회 분석, 결과 집계 |
| 증거 manifest | `evidence/case-manifest.json` | 파일 크기, SHA-256, 수집 정보 |
| Elastic 적재 | `logstash/pipeline/snort.conf` | JSON 입력과 Elasticsearch 출력 |
| 대시보드 자동 생성 | `scripts/setup-kibana.ps1` | data view와 Lens panel 생성 |
| CI 회귀 검사 | `.github/workflows/validate.yml` | PCAP 재분석과 평가 실패 조건 |

## 18. 직접 해 볼 실습

### 실습 1: 한 경보를 원본 packet까지 추적하기

1. Kibana에서 `doip_unauthorized_diagnostic` 경보의 시각과 주소를 확인한다.
2. `alerts/normalized-alerts.jsonl`에서 같은 scenario를 찾는다.
3. Snort와 Suricata 원본 경보에서 SID `1000007`을 찾는다.
4. Wireshark에서 `tcp.port == 13400`으로 packet을 찾는다.
5. DoIP header와 UDS service `0x2E` 위치를 설명한다.

완료 기준: “Kibana 숫자”에서 끝나지 않고 정규화 event → 원본 IDS alert → PCAP byte까지 역추적할 수 있어야 한다.

### 실습 2: 정상과 공격의 차이 확인하기

1. `attack-traffic.pcap`과 `benign-traffic.pcap`을 각각 연다.
2. ICMP request 수를 비교한다.
3. 공격 DoIP의 `0x2E`와 정상 DoIP의 `0x22`를 비교한다.
4. SOME/IP-SD FindService와 OfferService의 entry type 차이를 확인한다.
5. 정상 PCAP에서 IDS 경보가 0건인지 확인한다.

완료 기준: 규칙이 어떤 byte와 빈도를 공격 조건으로 삼는지 설명할 수 있어야 한다.

### 실습 3: 임계치 변경의 영향 확인하기

1. ICMP `detection_filter`의 count가 현재 몇인지 확인한다.
2. 규칙을 수정하지 말고, count를 2 또는 5로 바꿨을 때 결과를 예상해 적는다.
3. 정상 1회와 공격 4회에서 예상되는 TP·FP·FN·TN을 계산한다.
4. 임계치가 낮을 때와 높을 때의 운영상 장단점을 설명한다.

완료 기준: “낮을수록 좋다”가 아니라 오탐과 미탐의 trade-off를 설명할 수 있어야 한다.

### 실습 4: PCAP 무결성 확인하기

```powershell
python -m forensics.cli verify-fixture `
  --pcap evidence/lab-traffic.pcap `
  --checksum evidence/lab-traffic.pcap.sha256
```

확인할 항목:

- expected hash와 actual hash가 같은가
- packet count와 file bytes는 얼마인가
- link type과 timestamp precision은 무엇인가
- hash가 다르면 분석을 계속해도 되는가

정답 방향: hash가 기준값과 다르면 변경 원인을 확인하기 전까지 같은 증거라고 전제해서는 안 된다.

### 실습 5: 5회 반복 평가 읽기

`evidence/evaluation/detection-metrics.json`에서 다음 값을 직접 찾는다.

```text
unique_attack_scenarios
unique_benign_scenarios
repeated_runs
observations
confusion_matrix
repeatability
```

그다음 아래 질문에 답한다.

- observations가 80인 이유는 무엇인가?
- unique scenario가 16이 아니라 공격 8·정상 8로 표시되는 이유는 무엇인가?
- 한 번의 정상 run에서 경보가 하나 발생하면 FP와 FPR은 어떻게 바뀌는가?
- 5회 중 한 번 공격을 놓치면 repeatability는 어떻게 바뀌는가?

## 19. 분석 보고서 작성 순서

사건이나 실습 결과를 설명할 때는 다음 순서가 읽기 쉽다.

1. 범위: 언제, 어느 망, 어떤 시스템을 분석했는가
2. 원본: PCAP 파일명, 크기, SHA-256은 무엇인가
3. 관찰: 어떤 주소·포트·protocol에서 무엇을 봤는가
4. 탐지: 어느 규칙과 SID가 경보를 만들었는가
5. 해석: 왜 의심스럽고 어떤 정상 가능성이 있는가
6. 교차 확인: 다른 IDS나 로그에서도 같은 행위를 확인했는가
7. 영향: 현재 증거로 말할 수 있는 범위는 어디까지인가
8. 조치: 추가로 수집하거나 차단할 항목은 무엇인가
9. 한계: 수집하지 못했거나 단정할 수 없는 것은 무엇인가

좋지 않은 표현:

> DoIP 공격을 100% 탐지했다.

범위가 드러나는 표현:

> 로컬 합성 DoIP 공격 fixture 1종을 5회 재분석했으며 Snort와 Suricata에서 모두 SID 1000007 경보를 확인했다. 실제 ECU와 운영망 정상 트래픽은 평가 범위에 포함하지 않았다.

## 20. 학습 완료 체크리스트

### 네트워크·포렌식

- [ ] TCP 3-way handshake와 SYN scan의 차이를 설명할 수 있다.
- [ ] TCP와 UDP의 차이를 이 프로젝트 packet으로 설명할 수 있다.
- [ ] capture filter와 display filter의 차이를 안다.
- [ ] PCAP global header와 packet record의 역할을 안다.
- [ ] 원본 증거와 파생 증거를 구분할 수 있다.
- [ ] SHA-256이 보장하는 것과 보장하지 않는 것을 설명할 수 있다.

### 탐지 엔지니어링

- [ ] Snort/Suricata rule header와 option을 읽을 수 있다.
- [ ] `flow`, `content`, `flags`, `detection_filter`의 역할을 안다.
- [ ] 같은 packet을 두 IDS로 분석한 이유를 설명할 수 있다.
- [ ] 경보 개수와 탐지 정확도가 다른 개념임을 설명할 수 있다.
- [ ] threshold 조정에 따른 FP/FN trade-off를 설명할 수 있다.

### 자동차 Ethernet

- [ ] DoIP와 UDS의 관계를 설명할 수 있다.
- [ ] UDS `0x22`, `0x27`, `0x2E`의 기본 용도를 안다.
- [ ] SOME/IP와 SOME/IP-SD의 차이를 설명할 수 있다.
- [ ] FindService와 OfferService를 구분할 수 있다.
- [ ] `0x2E`나 FindService만으로 공격을 확정하면 안 되는 이유를 안다.

### 데이터·평가

- [ ] Logstash, Elasticsearch, Kibana의 역할을 구분할 수 있다.
- [ ] TP, TN, FP, FN을 예시로 계산할 수 있다.
- [ ] recall, precision, FPR 공식을 설명할 수 있다.
- [ ] 80 observations와 고유 시나리오 수를 구분할 수 있다.
- [ ] 반복성과 재현성의 차이를 설명할 수 있다.
- [ ] 이 프로젝트 수치의 적용 범위와 한계를 말할 수 있다.
