# Technical Case Study

## 1. 프로젝트 배경

네트워크 보안 도구를 각각 설치하는 것만으로는 패킷이 어떤 과정을 거쳐 탐지 이벤트와 검색 가능한 데이터로 바뀌는지 설명하기 어렵습니다. 이 프로젝트는 공격 트래픽 생성, 증거 보존, IDS 탐지, 데이터 정규화, 검색·시각화를 하나의 재현 가능한 흐름으로 연결하기 위해 만들었습니다.

핵심 질문은 다음과 같습니다.

- 공격자와 피해 서버를 외부망에서 격리할 수 있는가?
- 원본 PCAP과 탐지 결과의 무결성을 함께 증명할 수 있는가?
- Snort 고유 JSON을 검색하기 쉬운 공통 필드로 정규화할 수 있는가?
- 다른 개발자도 한 번의 명령으로 같은 결과를 재현할 수 있는가?

## 2. 구현 범위

| 영역 | 구현 내용 |
|---|---|
| 네트워크 | 고정 IP를 사용하는 Docker 격리망 `10.77.0.0/24` |
| 트래픽 | ICMP, HTTP 관리 경로 probe, 제한형 SYN scan |
| 수집 | Kali의 `tcpdump`로 PCAP 생성, `tshark`로 분석 |
| 탐지 | Snort 3 커스텀 규칙 3개와 오프라인 PCAP 분석 |
| 파이프라인 | Logstash를 통한 Snort JSON → ECS 유사 필드 변환 |
| 저장/검색 | 일자별 Elasticsearch 인덱스와 Kibana 데이터 뷰 |
| 자동화 | PowerShell 실행·종료·Kibana 설정, Node 화면 캡처 |
| 품질 | GitHub Actions에서 Compose, JSON, 해시, 스크립트 구문 검증 |

## 3. 주요 설계 의사결정

### 트래픽 생성망과 분석망 분리

`lab_net`은 `internal: true`로 구성해 테스트 트래픽이 외부로 라우팅되지 않도록 했습니다. Elastic Stack은 별도의 `soc_net`에 배치하고, Kibana와 Elasticsearch 포트는 `127.0.0.1`에만 게시했습니다.

이 구조는 공격 재현 영역과 분석 영역의 책임을 분리하며, 로컬 실습의 오용 가능성을 낮춥니다.

### Snort 오프라인 분석

Snort를 인라인 센서로 연결하는 대신 저장된 PCAP을 분석하도록 구성했습니다. 동일한 증거 파일을 반복 분석할 수 있어 규칙 변경 전후 결과 비교와 디버깅이 쉬워집니다. 또한 Snort 컨테이너는 `network_mode: none`으로 실행해 분석 중 외부 통신을 차단했습니다.

### 증거와 이벤트를 함께 버전 관리

PCAP, SHA-256, nmap 결과, Snort JSON을 작은 샘플 증거 세트로 저장했습니다. 포트폴리오 검토자는 전체 스택을 실행하지 않아도 실제 입력과 결과를 확인할 수 있습니다.

### ECS 유사 필드 정규화

Logstash에서 `src_addr`, `dst_addr`, `sid`, `msg` 같은 Snort 필드를 다음 구조로 변환했습니다.

| Snort | 정규화 필드 |
|---|---|
| `src_addr` | `source.ip` |
| `dst_addr` | `destination.ip` |
| `src_port` / `dst_port` | `source.port` / `destination.port` |
| `proto` | `network.transport` |
| `sid` | `rule.id` |
| `msg` | `rule.description` |
| `priority` | `event.severity` |

이 변환으로 Kibana KQL에서 IP, 포트, 규칙, 프로토콜을 일관된 방식으로 검색할 수 있습니다.

## 4. 트러블슈팅 사례

### Docker 가상 NIC 체크섬 오프로딩

초기 Snort 분석에서 HTTP payload 규칙이 예상대로 발생하지 않았습니다. Docker 가상 NIC에서 캡처한 패킷의 체크섬 상태가 원인이었고, 오프라인 분석 명령에 `-k none`을 적용해 Snort가 캡처 파일의 체크섬 오류를 무시하도록 해결했습니다.

### WSL 저장소의 읽기 전용 전환

Elastic 이미지 압축 해제 중 호스트 드라이브 여유 공간이 0이 되면서 Docker 저장소가 `read-only file system` 상태로 전환됐습니다. 호스트 디스크 공간을 확보하고 WSL/Docker를 재시작한 뒤 이미지 계층을 다시 받아 복구했습니다.

이 경험을 README의 장애 대응 절차와 디스크 사전 요구 사항에 반영했습니다.

### Kibana 최초 실행 시간

Kibana 9의 최초 플러그인 초기화와 saved object migration은 Elasticsearch 적재 완료보다 오래 걸렸습니다. 단순 포트 오픈 대신 `/api/status`의 `available` 상태를 확인하도록 `setup-kibana.ps1`을 구현했고, 데이터 뷰 생성까지 자동화했습니다.

## 5. 검증 결과

| 지표 | 결과 |
|---|---:|
| PCAP 패킷 | 84 |
| PCAP 크기 | 6,778 bytes |
| Snort 규칙 | 3 |
| Snort 경보 | 30 |
| Elasticsearch 문서 | 30 |
| PCAP SHA-256 검증 | 일치 |
| Kibana 상태 | available |

탐지 분포는 ICMP 3건, HTTP probe 1건, SYN scan 26건입니다. 원본 JSON 30개 행과 Elasticsearch 문서 30건이 일치해 수집부터 적재까지 이벤트 손실이 없음을 확인했습니다.

## 6. 품질과 재현성

GitHub Actions는 전체 Elastic 이미지를 실행하지 않고도 다음 항목을 빠르게 검증합니다.

- Docker Compose 구성 유효성
- Snort JSON 30개 행 파싱
- PCAP SHA-256 일치
- Bash, Node.js, PowerShell 스크립트 구문

로컬 통합 검증은 `scripts/run-lab.ps1`이 담당합니다. 실행이 끝나면 Elasticsearch 문서 수와 Kibana 준비 상태까지 확인합니다.

## 7. 한계와 확장 방향

- 현재 Snort는 오프라인 IDS이며 인라인 차단은 수행하지 않습니다.
- 트래픽은 고정된 소규모 시나리오이므로 정상·악성 데이터 다양성이 제한적입니다.
- 인증을 비활성화한 로컬 실습 설정이므로 운영 환경에는 TLS, 계정, secret 관리가 필요합니다.

확장 우선순위는 다음과 같습니다.

1. Brute force, DNS tunneling, web exploit 시나리오 추가
2. Suricata EVE JSON과 Snort 결과 비교
3. Kibana Lens 기반 탐지 분포 대시보드 자동 생성
4. Sigma 규칙 또는 ATT&CK technique 매핑
5. CI에서 경량 PCAP 회귀 테스트 수행

## 8. 인터뷰용 요약

> Docker 격리망에서 Kali 공격 트래픽을 생성하고 PCAP을 보존한 뒤, Snort 3 커스텀 규칙으로 탐지해 Logstash와 Elasticsearch로 정규화·적재하고 Kibana에서 분석하는 재현 가능한 포렌식 파이프라인을 구축했습니다. PCAP 해시, JSON 행 수, Elasticsearch 문서 수를 교차 검증했으며 Docker 체크섬 오프로딩과 WSL 디스크 장애도 직접 진단해 자동화와 운영 문서에 반영했습니다.
