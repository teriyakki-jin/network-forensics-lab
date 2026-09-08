# 자동차·생산망 네트워크 포렌식 위협 모델

## 목적과 범위

이 문서는 기업 IT, 생산 OT, 차량 Ethernet 사이에서 발생할 수 있는 네트워크 침해 징후를 안전한 로컬 fixture로 재현하기 위한 모델입니다. 실제 현대모비스 네트워크나 차량 구조를 복제하지 않으며, 특정 기업의 내부 통제를 추정하지 않습니다.

프로젝트가 검증하는 질문은 다음과 같습니다.

- 기업망에서 시작된 탐색 행위가 생산·차량 네트워크 경계로 이동하는 흐름을 식별할 수 있는가?
- 비인가 DoIP 진단 명령과 SOME/IP 서비스 탐색을 PCAP에서 재현할 수 있는가?
- 서로 다른 IDS 결과를 동일 사건·시나리오 기준으로 비교할 수 있는가?
- 원본과 파생 증거의 무결성 및 수집 맥락을 자동으로 보존할 수 있는가?

## 자산과 신뢰 경계

| 자산 | 실습 구성 | 주요 보안 속성 |
|---|---|---|
| 엔지니어링 단말 | Kali traffic generator | 명령 주체 식별, 허가된 목적지 제한 |
| 기업 웹 서비스 | Nginx victim | 인증, 입력 검증, 접근 기록 |
| 이름 해석 서비스 | CoreDNS | 비정상 query 식별 |
| 차량 Gateway | Python TCP/UDP simulator | 진단 주체 인증, 허용 서비스 제한 |
| 원본 증거 | `lab-traffic.pcap` | 무결성, 수집시각, 재현성 |
| 탐지 증거 | Snort·Suricata alerts | 규칙 버전, 공통 스키마, 사건 연결성 |

공격 구성은 `10.77.0.0/24` Docker internal network 안에서만 실행됩니다. 차량 Gateway는 호스트 포트를 공개하지 않으며 Snort와 Suricata는 네트워크가 없는 컨테이너에서 PCAP만 분석합니다.

## 대표 공격 흐름

```text
엔지니어링 단말 탐색
  → 웹 관리 경로 및 인증 시도
  → DNS 터널 형태의 유출 징후
  → 차량 Gateway DoIP 진단 명령
  → SOME/IP 서비스 탐색
  → IDS 교차 분석
  → 사건 타임라인 및 증거 manifest
```

각 행위는 독립적인 합성 fixture입니다. 현재 버전은 실제 계정 탈취나 구간 간 침투 성공을 재현하지 않으므로 전체 흐름을 실제 causal attack chain으로 표현하지 않습니다.

## 위협과 통제

| 위협 | ATT&CK 관점 | 예방·탐지 통제 | 증거 |
|---|---|---|---|
| 네트워크 탐색 | Enterprise T1046 | 세그멘테이션, IDS scan rule | SID 1000003 |
| DNS 기반 유출 징후 | Enterprise T1071.004 | DNS monitoring, 긴 label 탐지 | SID 1000005 |
| 비인가 DoIP 진단 명령 | ICS T1692.001 | 진단 주체 허용목록, command inspection | SID 1000007 |
| SOME/IP 서비스 탐색 | ICS T0846.003 | 정적 통신 관계, discovery monitoring | SID 1000008 |
| PCAP 또는 보고서 변조 | 증거 무결성 | SHA-256 artifact manifest | `case-manifest.json` |

ATT&CK 매핑은 공격 행위 설명을 표준화하기 위한 것이며 UNECE R155 또는 ISO/SAE 21434 준수를 주장하지 않습니다.

## 증거 취급

`case-manifest.json`은 다음을 기록합니다.

- 사건번호 `NF-AUTO-LAB`
- UTC 수집시각과 sensor ID
- Snort·Suricata 버전
- PCAP, checksum, 정규화 경보, 비교 결과, Sigma 검증 결과의 SHA-256

`incident-timeline.json`은 두 IDS의 정규화 이벤트를 시간순으로 정렬합니다. 원본 PCAP은 변경하지 않으며 모든 분석 결과는 파생 증거로 취급합니다.

## 현재 한계와 다음 검증

- 합성 공격 8종을 포함한 단일 PCAP 회귀이며 운영망 탐지 정확도가 아닙니다.
- 정상 전용 PCAP이 아직 분리되지 않아 FPR을 제시하지 않습니다.
- 차량 Gateway는 DoIP·SOME/IP 학습용 시뮬레이터이며 ECU 동작을 구현하지 않습니다.
- 다음 단계에서는 정상 진단·정상 서비스 탐색 fixture를 별도 PCAP으로 만들고 시나리오 단위 confusion matrix를 5회 이상 반복 측정합니다.
