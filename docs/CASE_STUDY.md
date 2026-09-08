# Technical Case Study

## 1. 문제 정의

네트워크 보안 도구를 각각 설치하는 것만으로는 “기업·생산·차량 네트워크에서 같은 패킷이 서로 다른 IDS에 어떻게 탐지되고, 그 결과를 어떻게 신뢰할 수 있는가”를 설명하기 어렵습니다. 이 프로젝트의 목표는 공격 트래픽 생성, 증거 보존, 다중 IDS 탐지, 표준 매핑, 사건 타임라인, 검색·시각화를 하나의 반복 가능한 흐름으로 연결하는 것이었습니다.

핵심 질문은 다음과 같습니다.

- 실습 트래픽을 외부망과 확실히 분리할 수 있는가?
- 같은 PCAP에 대한 Snort와 Suricata 결과를 동일 기준으로 비교할 수 있는가?
- 원본 PCAP과 파생 증거가 서로 일치함을 자동 검증할 수 있는가?
- ATT&CK, Sigma, Kibana를 코드로 재생성할 수 있는가?
- 새 규칙이 기존 시나리오를 깨뜨리면 PR 단계에서 잡을 수 있는가?

## 2. 최종 구현 범위

| 영역 | 구현 |
|---|---|
| 격리망 | Docker `internal: true`, `10.77.0.0/24`, 고정 IP |
| 테스트 트래픽 | 기존 6종 + 합성 DoIP 진단 명령, SOME/IP-SD 서비스 탐색 |
| 차량 Gateway | 격리 TCP 13400·UDP 30490 응답 시뮬레이터 |
| 증거 수집 | Kali `tcpdump`, PCAP SHA-256, binary header, artifact manifest |
| 탐지 | Snort 3·Suricata 8 동일 PCAP 오프라인 분석 |
| 정규화 | Python 공통 이벤트 스키마, 민감 인증 원문 제외 |
| 표준 매핑 | MITRE ATT&CK·ATT&CK for ICS catalog, 시나리오별 Sigma 규칙 |
| 분석 | Logstash, Elasticsearch, Kibana Lens dashboard as code |
| 자동화 | 1-command PowerShell runner, 사건 타임라인, GitHub Actions PCAP regression |

## 3. 보안 경계

### 공격망

Kali, Nginx victim, CoreDNS는 외부 라우팅이 없는 `lab_net`에서만 통신합니다. 공격 시나리오는 `10.77.0.10`과 `10.77.0.53`만 대상으로 삼습니다.

### 분석 경계

Snort와 Suricata는 `network_mode: none`으로 실행됩니다. 두 엔진은 캡처가 끝난 PCAP만 읽으므로 분석 단계에서 외부 네트워크 접근이 필요하지 않습니다.

### 관리 인터페이스

Elasticsearch와 Kibana 포트는 `127.0.0.1`에만 바인딩합니다. 인증을 비활성화한 로컬 랩이므로 외부 인터페이스 노출을 허용하지 않습니다.

## 4. 탐지 모델

`detection/rule-catalog.json`을 규칙 메타데이터의 단일 기준으로 사용합니다.

```text
scenario
  ├─ Snort SID
  ├─ Suricata SID
  ├─ title
  └─ ATT&CK tactic / technique
```

Python 정규화기는 엔진별 원본을 다음 공통 필드로 변환합니다.

```text
@timestamp
engine
scenario
source.ip / source.port
destination.ip / destination.port
network.transport
rule.id / rule.description
threat.tactic.name
threat.technique.id / threat.technique.name
```

HTTP Basic 인증 원문처럼 자격 증명이 포함될 수 있는 payload는 정규화 증거에 복사하지 않습니다.

## 5. 실제 검증 결과

현재 커밋 fixture 결과:

| 항목 | 결과 |
|---|---:|
| PCAP packets | 168 |
| PCAP bytes | 16,756 |
| Snort alerts | 45 |
| Suricata alerts | 45 |
| 양쪽 엔진에서 탐지된 시나리오 | 8 / 8 |
| 시나리오별 alert delta | 모두 0 |
| Sigma rules | 8 valid |
| 사건 증거 | 5 artifacts hashed, 90 timeline events |
| Python tests | 34 passed |
| 전체 coverage | 93% |

이 결과는 로컬 회귀 fixture에 한정됩니다. 운영망 전체의 탐지율이나 오탐률로 일반화하지 않습니다.

## 6. 해결한 통합 장애

### Elasticsearch 시작 경합

`docker compose up -d`는 컨테이너 프로세스가 시작됐음을 의미할 뿐 REST API 준비를 보장하지 않았습니다. 최초 실행에서 인덱스 삭제 요청이 JVM 부팅보다 먼저 도착해 연결이 닫혔습니다.

해결:

- `/_cluster/health?wait_for_status=yellow`를 반복 확인
- 제한 시간 내 준비되지 않으면 명시적 실패
- 준비 확인 이후에만 인덱스 작업 수행

### Elasticsearch 9 wildcard 삭제 차단

Elasticsearch 9의 안전 설정은 `DELETE /ids-alerts-*`를 거부했습니다.

해결:

- `_cat/indices/ids-alerts-*`로 후보 조회
- `ids-alerts-*` 접두사 재검증
- URL encoding한 정확한 인덱스 이름만 개별 삭제

이 방식은 편리한 wildcard 삭제보다 범위가 명확하고 안전합니다.

### Kibana 초기화와 dashboard drift

Kibana는 최초 실행 때 플러그인과 saved object migration에 시간이 필요합니다. 수동으로 만든 화면은 다른 환경에서 재현되지 않았습니다.

해결:

- `/api/status`의 `available` 상태 대기
- 데이터 뷰를 고정 ID `ids-alerts`로 생성
- 공식 Dashboards API에 고정 ID `network-forensics-overview`로 upsert
- metric, pie, data table Lens 패널을 코드로 선언
- Headless Chrome으로 실제 렌더링을 확인한 후 README screenshot 생성

### 변동 가능한 PCAP과 취약한 테스트

초기 CLI 테스트는 패킷 수 `84`를 하드코딩했습니다. 새 시나리오를 추가해 PCAP을 다시 만들자 정상 변경인데도 테스트가 실패했습니다.

해결:

- 특정 패킷 수 대신 `packets > 0` 검증
- PCAP parser가 계산한 파일 크기와 hash 검증기의 byte 수 일치 확인
- 상세 수치는 생성된 evidence JSON에서 기록

## 7. TDD와 품질 게이트

구현은 다음 RED → GREEN 순서로 진행했습니다.

1. 공통 이벤트와 비교 결과에 대한 단위 테스트
2. 시나리오 단위 confusion matrix와 증거 경계 검증
3. 사건 manifest 및 타임라인 CLI 테스트
4. CLI fixture, Sigma 검증 테스트
5. Compose 격리, 이미지 고정, rule coverage 계약 테스트
6. Elasticsearch readiness와 정확한 index delete 계약 테스트
7. Kibana Lens dashboard/capture 계약 테스트

GitHub Actions는 실제 Snort·Suricata 컨테이너를 실행해 커밋된 PCAP을 다시 분석합니다. Python 테스트만 통과하고 IDS 규칙이 깨지는 상황을 막기 위한 회귀 게이트입니다.

## 8. 포트폴리오 관점의 차별성

이 프로젝트의 핵심은 도구 수가 아니라 증거의 연결성입니다.

```text
Threat fixture
  → immutable PCAP check
  → two IDS engines
  → normalized events
  → ATT&CK + Sigma
  → Elastic evidence
  → CI regression
```

따라서 “Snort를 설치했다”보다 다음 역량을 보여 줍니다.

- 안전한 테스트 경계 설계
- 엔진별 데이터 모델 통합
- 디지털 증거 무결성 검증
- detection-as-code와 dashboard-as-code
- 실패 조건을 자동화 계약으로 전환하는 디버깅

## 9. 한계와 다음 연구 주제

- 소규모 합성 fixture이므로 실제망 FPR·recall·처리량을 측정하지 않습니다.
- 암호화 트래픽 복호화와 TLS inspection은 범위 밖입니다.
- IDS는 오프라인 탐지이며 IPS 차단을 수행하지 않습니다.
- 다음 확장 시 실제 공개 PCAP corpus와 benign baseline을 분리해 precision/recall을 측정할 수 있습니다.
- 대규모 evidence는 Git LFS 또는 object storage와 chain-of-custody metadata가 필요합니다.
- 정상 전용 fixture를 분리하기 전에는 FPR·precision을 제시하지 않습니다.
