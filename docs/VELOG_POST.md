<!--
Velog 제목: Docker로 만드는 재현 가능한 네트워크 포렌식 랩: Kali·Snort 3·Elastic Stack
Velog 태그: 네트워크보안, 디지털포렌식, Snort, Wireshark, ELK, Docker, KaliLinux
시리즈 제안: 보안 프로젝트
-->

# Docker로 만드는 재현 가능한 네트워크 포렌식 랩: Kali·Snort 3·Elastic Stack

보안 도구를 각각 설치해 보는 것과, 하나의 패킷이 **수집 → 탐지 → 정규화 → 저장 → 분석**되는 전체 흐름을 직접 구축하는 것은 꽤 다른 경험이다.

이번 프로젝트에서는 Docker 격리망 안에서 Kali Linux로 테스트 트래픽을 만들고, PCAP으로 증거를 보존한 뒤, Snort 3와 Elastic Stack을 이용해 탐지 결과를 분석하는 네트워크 포렌식 랩을 만들었다.

최종적으로 다음 결과를 재현했다.

- PCAP 84 packets, 6,778 bytes
- Snort 커스텀 규칙 3개
- Snort JSON 경보 30건
- Elasticsearch 문서 30건
- PCAP SHA-256 무결성 검증
- Kibana 데이터 뷰 자동 생성
- GitHub Actions 기반 정적 검증

프로젝트 전체 코드는 아래 저장소에서 확인할 수 있다.

> [GitHub: network-forensics-lab](https://github.com/teriyakki-jin/network-forensics-lab)

## 완성된 분석 화면

![Kibana Discover에서 확인한 Snort 경보 30건](https://raw.githubusercontent.com/teriyakki-jin/network-forensics-lab/main/assets/kibana-discover.png)

위 화면은 예시 이미지를 따로 만든 것이 아니라, 프로젝트를 직접 실행한 뒤 Kibana Discover에서 `snort-alerts-*` 데이터 뷰와 30개의 탐지 이벤트를 확인한 결과다.

## 프로젝트를 시작한 이유

처음에는 Kali Linux, Wireshark, Snort, ELK를 각각 실행해 보는 수준으로 생각했다. 하지만 도구별 사용법만 나열하면 포렌식 과정 전체를 설명하기 어렵고, 다른 환경에서 같은 결과를 재현하기도 힘들었다.

그래서 다음 네 가지 질문을 프로젝트의 기준으로 잡았다.

1. 테스트 트래픽이 외부망으로 나가지 않도록 격리할 수 있는가?
2. 탐지의 원본인 PCAP과 분석 결과를 함께 보존할 수 있는가?
3. Snort JSON을 Kibana에서 검색하기 좋은 필드로 변환할 수 있는가?
4. 다른 사용자도 한 번의 명령으로 같은 결과를 재현할 수 있는가?

이 기준을 만족시키기 위해 단순 설치 문서가 아니라 실행 가능한 랩과 검증 가능한 샘플 증거를 함께 저장했다.

## 전체 아키텍처

```text
┌──────────────── Docker 격리망: lab_net (10.77.0.0/24) ────────────────┐
│                                                                       │
│  Kali Linux 10.77.0.20  ── ICMP / HTTP probe / SYN scan ──▶  Nginx   │
│          │                                             10.77.0.10     │
│          └──────────── tcpdump / tshark ───────────▶ PCAP             │
└───────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                        Snort 3 오프라인 분석
                         (network_mode: none)
                                      │
                                      ▼
                              Snort JSON alerts
                                      │
                                      ▼
┌────────────────────── 분석망: soc_net ────────────────────────────────┐
│  Logstash ──▶ Elasticsearch ──▶ Kibana Discover                      │
└───────────────────────────────────────────────────────────────────────┘
```

공격 트래픽을 만드는 영역과 분석 영역을 분리했다. `lab_net`은 Docker 내부망으로 만들고, Elastic Stack은 별도의 `soc_net`에 배치했다.

## 사용한 기술

| 영역 | 기술 | 역할 |
|---|---|---|
| 테스트 환경 | Docker Compose | 네트워크와 컨테이너 재현 |
| 트래픽 생성 | Kali Linux, ping, curl, nmap | 승인된 테스트 트래픽 생성 |
| 패킷 수집 | tcpdump | PCAP 증거 생성 |
| 패킷 분석 | Wireshark, tshark | 프로토콜과 세션 분석 |
| IDS | Snort 3 | 커스텀 규칙 기반 탐지 |
| 데이터 처리 | Logstash | JSON 파싱과 필드 정규화 |
| 저장 | Elasticsearch | 탐지 이벤트 색인 |
| 시각화 | Kibana | KQL 검색과 이벤트 확인 |
| 자동화 | PowerShell, Node.js | 실행·설정·화면 캡처 |
| 품질 관리 | GitHub Actions | 구성·증거·스크립트 검증 |

## 1. 외부로 나가지 않는 테스트 망 구성

테스트 트래픽을 만들 때 가장 먼저 고려한 것은 기능보다 **범위 제한**이었다. 실습용 Kali와 Nginx는 고정 IP를 사용하며, 네트워크에 `internal: true`를 적용했다.

```yaml
networks:
  lab_net:
    internal: true
    ipam:
      config:
        - subnet: 10.77.0.0/24
  soc_net: {}
```

```yaml
services:
  victim:
    image: nginx:1.27-alpine
    networks:
      lab_net:
        ipv4_address: 10.77.0.10

  kali:
    networks:
      lab_net:
        ipv4_address: 10.77.0.20
```

Elasticsearch와 Kibana는 호스트 전체가 아니라 localhost에만 포트를 게시했다.

```yaml
ports:
  - "127.0.0.1:9200:9200"
```

```yaml
ports:
  - "127.0.0.1:5601:5601"
```

이 구성은 외부 시스템을 스캔하지 않고, 정해진 두 컨테이너 사이에서만 트래픽이 생성되도록 제한한다.

## 2. 트래픽 생성과 PCAP 수집

트래픽 시나리오는 결과를 쉽게 설명할 수 있도록 세 가지로 제한했다.

| 시나리오 | 생성 방법 | 목적 |
|---|---|---|
| ICMP Echo Request | `ping -c 3` | 기본 연결과 ICMP 탐지 확인 |
| HTTP admin probe | `GET /admin?cmd=id` | payload 문자열 탐지 확인 |
| 제한형 SYN scan | TCP 1~30번 포트 | 다중 SYN 패턴 탐지 확인 |

Kali 컨테이너의 `tcpdump`를 먼저 실행한 뒤 트래픽을 만들고, 캡처가 끝나면 PCAP의 SHA-256을 계산한다.

```powershell
$Hash = Get-FileHash .\evidence\lab-traffic.pcap -Algorithm SHA256
$Hash.Hash.ToLowerInvariant()
```

현재 저장된 샘플의 해시는 다음과 같다.

```text
504c3711f3244644293fc261d7424b3971dbddb2eb8402fcfe2ad1c57877bbdd
```

해시는 `lab-traffic.pcap.sha256`에도 저장한다. 원본 파일이 변경되면 이후 검증에서 바로 확인할 수 있다.

## 3. Snort 3 커스텀 규칙 작성

PCAP에 들어 있는 세 가지 행위를 확인하기 위해 다음 규칙을 작성했다.

```snort
alert icmp any any -> 10.77.0.10 any \
    (msg:"LAB ICMP Echo Request"; itype:8; sid:1000001; rev:1;)

alert tcp any any -> 10.77.0.10 80 \
    (msg:"LAB HTTP Admin Command Probe"; \
    content:"/admin?cmd=id"; sid:1000002; rev:3;)

alert tcp any any -> 10.77.0.10 any \
    (msg:"LAB TCP SYN Scan"; flags:S; \
    detection_filter:track by_src, count 5, seconds 60; \
    sid:1000003; rev:1;)
```

규칙별 탐지 결과는 다음과 같았다.

| SID | 탐지 내용 | 결과 |
|---:|---|---:|
| `1000001` | ICMP Echo Request | 3건 |
| `1000002` | HTTP admin command probe | 1건 |
| `1000003` | TCP SYN scan | 26건 |
|  | **합계** | **30건** |

Snort는 실시간 네트워크 인터페이스에 붙이지 않고, 저장된 PCAP을 오프라인으로 분석하도록 했다.

```yaml
snort:
  network_mode: none
```

이 방식은 같은 증거 파일로 규칙을 반복 검증할 수 있다는 장점이 있다. 규칙을 수정한 뒤에도 입력 PCAP이 같으므로 탐지 결과의 차이를 비교하기 쉽다.

## 4. Logstash에서 검색 가능한 필드로 변환

Snort의 원본 JSON 필드만 사용해도 저장은 가능하지만, Kibana에서 IP·포트·규칙을 일관되게 검색하기 위해 ECS와 유사한 구조로 정규화했다.

| Snort 원본 | 변환 필드 |
|---|---|
| `src_addr` | `source.ip` |
| `dst_addr` | `destination.ip` |
| `src_port` | `source.port` |
| `dst_port` | `destination.port` |
| `proto` | `network.transport` |
| `sid` | `rule.id` |
| `msg` | `rule.description` |
| `priority` | `event.severity` |

Logstash의 핵심 변환은 다음과 같다.

```text
mutate {
  rename => {
    "src_addr" => "[source][ip]"
    "dst_addr" => "[destination][ip]"
    "src_port" => "[source][port]"
    "dst_port" => "[destination][port]"
    "proto" => "[network][transport]"
    "sid" => "[rule][id]"
    "msg" => "[rule][description]"
    "priority" => "[event][severity]"
  }
}
```

이후 Kibana에서는 다음처럼 KQL을 사용할 수 있다.

```text
rule.id: 1000002
```

```text
source.ip: "10.77.0.20" and destination.ip: "10.77.0.10"
```

```text
network.transport: "tcp" and destination.port <= 30
```

## 5. 한 번의 명령으로 전체 파이프라인 실행

프로젝트 실행은 PowerShell 스크립트 하나로 묶었다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-lab.ps1
```

스크립트는 다음 순서로 동작한다.

1. Docker 엔진 확인
2. Kali와 Nginx 격리망 시작
3. `tcpdump` 패킷 캡처 시작
4. ICMP, HTTP probe, SYN scan 생성
5. PCAP SHA-256 기록
6. Snort 3 오프라인 분석
7. Elasticsearch 적재 건수 확인
8. Kibana 준비 상태 확인과 데이터 뷰 생성

단순히 컨테이너를 시작하는 데서 끝내지 않고, Elasticsearch 문서 수와 Kibana의 `/api/status`까지 확인한다. 실행이 완료됐다는 메시지가 나왔을 때 실제 분석 화면을 사용할 수 있도록 하는 것이 목표였다.

## 트러블슈팅 1: HTTP 규칙이 탐지되지 않았다

처음 Snort를 실행했을 때 ICMP와 SYN 경보는 발생했지만 HTTP payload 규칙이 기대대로 탐지되지 않았다.

규칙 문자열과 PCAP의 HTTP 요청을 비교했지만 내용은 일치했다. 원인은 Docker 가상 NIC에서 캡처된 패킷의 체크섬 상태였다. 컨테이너 네트워크에서는 체크섬 오프로딩 때문에 캡처 시점에 체크섬이 완성되지 않은 것처럼 보일 수 있다.

오프라인 분석 명령에 `-k none`을 적용해 캡처 파일의 체크섬 검사를 비활성화했다.

```sh
snort -k none -r /evidence/lab-traffic.pcap
```

이후 `/admin?cmd=id` 요청이 SID `1000002`로 정상 탐지됐다.

이 문제를 통해 “패킷 내용이 맞는데 규칙이 동작하지 않는다”면 규칙 문법뿐 아니라 캡처 환경과 NIC 오프로딩도 확인해야 한다는 것을 배웠다.

## 트러블슈팅 2: Docker 저장소가 읽기 전용으로 바뀌었다

Elastic 이미지를 내려받아 압축을 해제하는 과정에서 호스트 드라이브의 여유 공간이 모두 소진됐다. 그 결과 WSL 내부 Docker 저장소가 `read-only file system` 상태로 전환됐다.

다음 순서로 복구했다.

1. 호스트 디스크 공간 확보
2. WSL 종료
3. Docker Desktop 재시작
4. 이미지 계층 다시 다운로드
5. PCAP 해시와 탐지 결과 재검증

```powershell
wsl --shutdown
```

이 경험 이후 README 요구 사항에 충분한 디스크 공간을 명시하고, 실행 결과만이 아니라 증거 해시도 다시 확인하도록 했다.

## 트러블슈팅 3: Elasticsearch는 준비됐는데 Kibana는 열리지 않았다

Kibana 9의 첫 실행에서는 플러그인 초기화와 saved object migration 때문에 Elasticsearch보다 준비 시간이 길었다. 포트가 열렸는지만 확인하면 아직 사용할 수 없는 상태를 준비 완료로 잘못 판단할 수 있었다.

이를 해결하기 위해 `setup-kibana.ps1`에서 `/api/status`의 전체 상태가 `available`이 될 때까지 기다리도록 했다. 준비가 끝나면 `snort-alerts-*` 데이터 뷰를 생성하고 기본 데이터 뷰로 지정한다.

이미 데이터 뷰가 있다면 다시 만들지 않기 때문에 스크립트를 반복 실행해도 안전하다.

## Wireshark에서 원본 증거 확인

Kibana의 탐지 결과만 보는 것으로 끝내지 않고 `evidence/lab-traffic.pcap`을 Wireshark에서 열어 원본 패킷과 경보를 교차 확인했다.

유용했던 Display Filter는 다음과 같다.

```text
icmp && ip.src == 10.77.0.20
```

```text
http.request.uri contains "/admin"
```

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

CLI 환경에서는 같은 PCAP을 `tshark`로 확인할 수 있다.

```powershell
docker compose exec kali tshark -r /evidence/lab-traffic.pcap -Y 'http.request' -V
```

## 결과를 어떻게 검증했는가

파이프라인의 각 단계에서 다음 수치를 교차 확인했다.

| 검증 대상 | 결과 |
|---|---:|
| PCAP 패킷 | 84 |
| PCAP 크기 | 6,778 bytes |
| Snort JSON 행 | 30 |
| Elasticsearch 문서 | 30 |
| ICMP 경보 | 3 |
| HTTP probe 경보 | 1 |
| SYN scan 경보 | 26 |
| SHA-256 | 일치 |
| Kibana 상태 | available |

원본 PCAP에서 Snort JSON 30건이 만들어지고, Elasticsearch에도 30건이 적재됐다. 탐지 규칙별 합계도 30건으로 일치한다.

이런 교차 검증을 넣은 이유는 화면에 데이터가 보인다는 사실만으로 수집 과정에서 이벤트가 누락되지 않았다고 단정할 수 없기 때문이다.

## GitHub Actions로 최소 품질 보장하기

CI에서 Elastic Stack 전체를 실행하면 시간과 리소스가 많이 필요하다. 대신 커밋마다 빠르게 확인할 수 있는 검증을 분리했다.

- `docker compose config` 유효성
- Snort JSON 파싱과 30개 행 확인
- PCAP SHA-256 일치
- Snort 실행 셸 스크립트 구문
- Node.js 화면 캡처 스크립트 구문
- 모든 PowerShell 스크립트 구문

전체 통합 실행은 로컬의 `run-lab.ps1`이 담당하고, CI는 저장소가 깨진 상태로 병합되는 것을 빠르게 막는 역할을 맡는다.

## 설계하면서 고민한 트레이드오프

### 실시간 탐지 대신 오프라인 PCAP 분석

실시간성은 없지만 동일한 입력으로 규칙을 반복 검증할 수 있다. 포렌식과 규칙 개발 학습에는 재현성이 더 중요하다고 판단했다.

### 완전한 ECS 대신 필요한 필드부터 변환

모든 Snort 필드를 ECS에 맞추기보다 이번 시나리오에서 검색에 사용하는 IP, 포트, 프로토콜, 규칙 정보를 우선 변환했다. 운영 환경으로 확장한다면 ECS 호환성 검토가 추가로 필요하다.

### 전체 스택 CI 대신 경량 검증

CI 속도와 비용을 줄일 수 있지만 Elasticsearch와 Kibana의 런타임 호환성은 로컬 통합 실행에서 확인해야 한다. 향후에는 경량 PCAP 회귀 테스트를 CI에 추가할 예정이다.

## 아쉬운 점과 다음 단계

현재 프로젝트는 작은 실습 환경이기 때문에 다음과 같은 한계가 있다.

- Snort가 인라인 IPS가 아닌 오프라인 IDS로 동작한다.
- 정상 트래픽과 악성 트래픽의 종류가 제한적이다.
- Elasticsearch와 Kibana 인증을 비활성화한 로컬 전용 구성이다.
- Kibana Lens 대시보드는 아직 자동 프로비저닝하지 않는다.

다음 단계로는 아래 기능을 확장할 계획이다.

1. Brute force와 DNS tunneling 시나리오 추가
2. Suricata EVE JSON과 Snort 결과 비교
3. Kibana Lens 기반 탐지 현황 대시보드 구성
4. MITRE ATT&CK technique과 규칙 매핑
5. CI에서 PCAP 기반 Snort 회귀 테스트 실행

## 마무리

이번 프로젝트를 통해 도구 자체보다 **도구 사이의 데이터 흐름과 검증 방법**이 더 중요하다는 것을 배웠다.

Kali에서 만든 한 번의 요청이 PCAP에 기록되고, Snort 규칙에 탐지되고, Logstash에서 정규화된 뒤 Elasticsearch와 Kibana에서 검색되는 전체 과정을 직접 연결했다. 또한 체크섬 오프로딩, WSL 저장소 장애, Kibana 초기화 지연처럼 실제 구축 과정에서 발생한 문제를 원인별로 분석하고 자동화에 반영했다.

네트워크 포렌식이나 탐지 엔지니어링을 공부한다면 도구별 실습에서 멈추지 않고, 작은 환경이라도 **원본 증거 → 탐지 이벤트 → 분석 화면 → 검증 지표**를 하나의 재현 가능한 프로젝트로 만들어 보는 것을 추천한다.

> 전체 소스, 샘플 PCAP, Snort 경보, 실행 방법:  
> [https://github.com/teriyakki-jin/network-forensics-lab](https://github.com/teriyakki-jin/network-forensics-lab)
