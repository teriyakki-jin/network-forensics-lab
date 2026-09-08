# 자동차 Ethernet 네트워크 포렌식 위협 모델

## 범위

이 랩은 기업 IT 구간에서 시작된 이상 행위와 차량 Ethernet 구간의 비인가 진단·서비스 탐색을 한 환경에서 분석하기 위해 만들었다. 실제 기업망이나 차량을 복제하지 않으며, 모든 트래픽은 `10.77.0.0/24` Docker 내부망에서만 발생한다.

확인하려는 내용은 네 가지다.

- 네트워크 탐색과 인증 반복 같은 선행 징후를 PCAP에 남길 수 있는가
- DoIP 진단 명령과 SOME/IP-SD 탐색을 두 IDS가 같은 시나리오로 식별하는가
- 원본 PCAP과 분석 결과가 바뀌지 않았음을 해시로 확인할 수 있는가
- 정상 트래픽을 함께 분석했을 때 같은 규칙이 불필요한 경보를 만들지 않는가

## 자산과 경계

| 자산 | 랩 구성 | 확인할 사항 |
|---|---|---|
| 분석 단말 | Kali `10.77.0.20` | 목적지 제한, 명령 재현 가능성 |
| 웹 서비스 | Nginx `10.77.0.10` | 관리 경로 접근, 인증 반복, 입력값 공격 |
| DNS | CoreDNS `10.77.0.53` | 비정상 subdomain 질의 |
| 차량 Gateway | Simulator `10.77.0.30` | DoIP 진단 명령, SOME/IP-SD 탐색 |
| 원본 증거 | PCAP과 SHA-256 | 무결성, 수집 시각, 파일 구조 |
| 파생 증거 | IDS 경보·타임라인 | 규칙 버전, 출처, 사건 연결 |

`lab_net`은 `internal: true`로 설정했다. 차량 Gateway는 호스트 포트를 열지 않는다. Snort와 Suricata는 `network_mode: none` 상태에서 저장된 PCAP만 읽는다. Elasticsearch와 Kibana는 로컬 확인용이므로 `127.0.0.1`에만 바인딩한다.

## 시나리오 구성

```text
ICMP·SYN 네트워크 탐색
  → 웹 관리 경로 접근과 인증 반복
  → DNS 터널 형태 질의
  → DoIP 비인가 진단 명령
  → SOME/IP-SD 서비스 탐색
  → PCAP 보존과 IDS 교차 분석
```

위 흐름은 분석 순서를 설명하기 위한 것이다. 각 트래픽은 독립된 합성 시나리오이며, 실제 계정 탈취나 IT 구간에서 차량 구간으로의 침투 성공을 재현한 공격 체인은 아니다.

## 위협별 통제와 증거

| 위협 | ATT&CK 기준 | 랩에서 적용한 통제 | 남는 증거 |
|---|---|---|---|
| TCP 서비스 탐색 | Enterprise T1046 | 격리망, SYN 임계치 규칙 | SID 1000003 경보와 PCAP |
| DNS 기반 유출 징후 | Enterprise T1071.004 | 특정 query 형태 탐지 | SID 1000005 경보와 DNS packet |
| 비인가 DoIP 진단 | ICS T1692.001 | UDS 서비스 바이트 검사 | SID 1000007 경보와 TCP 13400 packet |
| SOME/IP-SD 탐색 | ICS T0846.003 | FindService entry 검사 | SID 1000008 경보와 UDP 30490 packet |
| 증거 파일 변경 | 해당 없음 | SHA-256, artifact manifest | checksum과 `case-manifest.json` |
| 규칙 변경 후 회귀 | 해당 없음 | 두 IDS 재분석, paired fixture 5회 평가 | CI 실행 결과와 metrics JSON |

ATT&CK 표기는 탐지 의도를 설명하기 위한 분류다. 이 프로젝트만으로 UNECE R155나 ISO/SAE 21434 준수를 주장하지 않는다.

## 증거 처리

원본 PCAP은 분석 입력으로만 사용한다. Snort·Suricata 경보, 공통 형식으로 바꾼 JSON, 비교 보고서와 타임라인은 모두 파생 증거로 취급한다.

`case-manifest.json`에는 사건번호, UTC 수집 시각, 센서 ID, 도구 버전과 주요 파일의 SHA-256이 들어간다. 공격·정상 평가용 PCAP에도 별도 checksum 파일을 둔다. `incident-timeline.json`은 두 엔진의 경보를 시간순으로 정렬한다.

## 평가 범위

현재 평가는 고유 공격 8개와 정상 8개를 각각 5회 분석한 결과다. 두 엔진 모두 TP 40, TN 40, FP 0, FN 0을 기록했다. recall 100%, precision 100%, FPR 0%는 이 fixture 안에서만 유효하다.

정상 트래픽의 종류와 실행 시간이 작기 때문에 운영망 오탐률로 사용할 수 없다. 차량 Gateway도 프로토콜 학습용 시뮬레이터다. 다음 단계에서는 공개 automotive PCAP과 장시간 정상 트래픽을 추가해 규칙이 다른 환경에서도 유지되는지 확인해야 한다.
