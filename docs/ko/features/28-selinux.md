# SELinux 타입 강제(TE), 도메인 전이 및 MLS 보안 컨텍스트

## 1. 개요 및 배경

**SELinux (Security-Enhanced Linux)**는 미국 국가안보국(NSA)과 오픈소스 커뮤니티가 협력하여 리눅스 커널에 구현한 플래그십 강제적 접근 제어(MAC) 시스템임. 전통적인 리눅스 임의적 접근 제어(DAC: UID/GID 기반 권한) 모델에서는 루트(Root, UID 0) 권한을 획득한 공격자가 시스템 전체를 무제한으로 장악할 수 있는 근본적 결함이 존재함.

SELinux는 커널의 모든 주체(프로세스)와 객체(파일, 소켓, IPC, 디렉터리 등)에 엄격한 **보안 컨텍스트(Security Context)**를 부여하고, **최소 권한 원칙(Principle of Least Privilege)**을 커널 레벨에서 강제함:
1. **타입 강제 (Type Enforcement, TE)**:
   - SELinux의 핵심 축으로, 프로세스의 도메인(Domain/Type)과 파일의 타입(Type) 간 허용 규칙이 정책 데이터베이스에 명시되어 있지 않으면 기본적으로 모든 접근을 차단함(Default Deny).
2. **다중 레벨 보안 (Multi-Level Security, MLS)**:
   - 벨-라파둘라(Bell-LaPadula, BLP) 기밀성 모델을 기반으로 기밀 등급(Sensitivity: $s_0 \sim s_{15}$)과 카테고리(Category: $c_0 \sim c_{1023}$)를 부여하여 데이터 유출을 방지함.
3. **도메인 전이 (Domain Transition)**:
   - 프로세스가 실행 파일(`execve`)을 실행할 때 사전에 인가된 진입점(Entrypoint) 규칙에 의해서만 통제된 방식으로 권한과 도메인이 전환되도록 강제함.
4. **접근 벡터 캐시 (Access Vector Cache, AVC)**:
   - 보안 서버(Security Server)의 정책 평가 결과를 커널 내 고속 해시 테이블에 캐싱하여 $O(1)$에 근접한 속도로 접근 판정을 수행함.

---

## 2. 실세계 비유: 국가 1급 정보기관의 비밀 등급 보안 구역

`SELinux`의 동작 구조는 **국가 최고 등급 군사정보국의 물리적 인가 및 취급 인가증 체계**에 비유할 수 있음:

```
[ 일반 DAC 환경 (신분증 만능주의: 기관장 패스 하나로 모든 금고 개방 가능) ]
  청소부(탈취된 서비스 계정): "기관장 신분증(UID 0 / Root)을 습득했습니다!"
  경비원(커널 DAC):          "기관장 패스이므로 1급 기밀실(/etc/shadow) 문을 열어드립니다."
  결과:                     하위 서비스가 침해당해 루트 권한을 얻으면 국가 전체 기밀이 즉시 유출됨!

[ SELinux Permissive 모드 (교육/감사 모드: 규정 위반을 적발하되 차단하지 않음) ]
  웹서버(httpd_t):  "인사팀 기밀 캐비닛(shadow_t)을 열고, 최상위 기밀문서(s1:c0)를 열람합니다!"
  보안감사관(AVC):  "보안 규정 위반 적발! (Type Enforcement 위반 및 No-Read-Up 위반)
                     단, 현재는 시스템 적응/감사 기간이므로 요청을 승인하고
                     블랙박스 감사 일지(auditd/dmesg)에 경고장을 기록합니다."
  결과:             차단은 발생하지 않으나 정책 튜닝 및 침해 분석을 위한 세부 AVC 감사 로그가 누적됨.

[ SELinux Enforcing 모드 (철통 강제 모드: 인가되지 않은 모든 동작 즉각 사살/거부) ]
  웹서버(httpd_t):  "인사팀 기밀 캐비닛(shadow_t) 문을 열겠습니다!"
  보안감사관(AVC):  "httpd_t 도메인은 오직 웹 콘텐츠(httpd_sys_content_t)만 열람 가능함!
                     shadow_t 열람 요청 즉시 기각 (-EACCES) 및 위반 경보 발령!"
  웹서버(httpd_t):  "그렇다면 관리자 영역으로 신분 위장(Domain Transition -> unconfined_t)을 시도합니다!"
  보안감사관(AVC):  "비인가 도메인 전이 시도 감지! 즉시 차단 (-EACCES)!"
  웹서버(httpd_t):  "동일 부서 내 상위 1급 비밀문서(s1:c0)를 몰래 훔쳐봅니다!"
  보안감사관(AVC):  "Bell-LaPadula No-Read-Up 원칙 위반! 하위 등급(s0)의 상위 등급(s1) 열람 차단!"

  최종 결과: 공격자가 루트 권한을 장악하더라도 격리된 httpd_t 감옥에 갇혀 시스템 다른 영역으로 이동 불가!
```

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 보안 컨텍스트 (Security Context) 구조

SELinux의 모든 주체와 객체는 다음과 같은 4단 레이블 문자열로 표현됨:

$$\text{user} : \text{role} : \text{type} : \text{level (MLS)}$$

| 구성 요소 | 예시 값 | 설명 |
| :--- | :--- | :--- |
| **User (사용자)** | `system_u`, `unconfined_u` | SELinux 고유의 논리적 아이덴티티 (리눅스 UID와 분리) |
| **Role (역할)** | `system_r`, `object_r` | RBAC(역할 기반 접근 제어)을 정의하며 특정 타입 집합만 가질 수 있음 |
| **Type / Domain** | `httpd_t`, `shadow_t` | Type Enforcement의 핵심 기준. 프로세스는 Domain, 객체는 Type이라 칭함 |
| **MLS Level** | `s0`, `s1:c0.c1023` | 기밀성 감도(Sensitivity) 및 구획(Category)을 표현하는 다중 레벨 |

---

### 3.2 타입 강제 (TE) 및 정책 규칙 문법

정책 파일(`te` 파일)에서 접근 권한은 명시적인 선언문으로만 부여됨:

```text
# 문법: rule_type source_type target_type : class { permissions };
allow httpd_t httpd_sys_content_t : file { read open getattr ioctl };

# 명시적 금지 규칙 (컴파일 타임에 정책 무결성 검증)
neverallow httpd_t shadow_t : file { read write execute };
```

- **Default Deny**: 허용 규칙(`allow`)이 존재하지 않는 모든 행위는 커널에서 즉시 거부됨.
- **Neverallow**: 보안 관리자가 절대 발생해서는 안 되는 정책 완화(예: 임의 프로세스의 shadow 파일 접근)를 방어하기 위한 불변 제약식임.

---

### 3.3 벨-라파둘라(Bell-LaPadula) MLS 기밀성 모델

MLS는 정보의 기밀성을 보장하기 위해 두 가지 수학적 공리를 강제함:

1. **단순 보안 속성 (Simple Security Property: No Read Up)**:
   - 주체 $S$는 자신의 감도 레벨 $L(S)$가 대상 객체 $O$의 감도 레벨 $L(O)$를 지배(Dominate, $\ge$)할 때만 읽기 가능함:
   $$L(S) \ge L(O) \iff S \text{ dominates } O$$
   - 하위 등급 프로세스($s0$)는 상위 기밀 문서($s1$)를 읽을 수 없음.
2. **스타 속성 ($\star$-Property: No Write Down)**:
   - 주체 $S$는 대상 객체 $O$의 감도 레벨이 자신의 감도 레벨을 지배할 때만 쓰기 가능함:
   $$L(O) \ge L(S)$$
   - 상위 기밀 프로세스($s1$)가 실수나 악의로 기밀 정보를 하위 문서($s0$)에 기록하여 누출하는 행위를 방지함.

---

### 3.4 접근 벡터 캐시 (Access Vector Cache, AVC) 파이프라인

커널 시스템 콜 진입 시 접근 판정은 고속 캐시를 통해 이루어짐:

```
[ 시스템 콜 진입 (예: sys_open) ]
              │
              ▼
   [ LSM 후크: selinux_file_open() ]
              │
              ▼
      [ AVC 캐시 검색 ] ──(캐시 적중: Hit)──► [ 빠른 허용 / 거부 판정 ]
              │ (Miss)
              ▼
    [ SELinux 보안 서버 ] ──► 정책 DB 및 MLS 제약 검사
              │
              ▼
     [ 결과 캐싱 및 AVC 기록 ] ──► 거부 시 audit(avc): denied 이벤트 생성
```

- **`permissive=0`**: Enforcing 모드. 접근 거부 시 `-EACCES` 반환 및 감사 기록.
- **`permissive=1`**: Permissive 모드. 위반 내역을 감사 로그에 기록하되 요청은 승인(`return 0`).

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 SELinux의 보안 컨텍스트 해석, AVC 캐시 파이프라인, Type Enforcement 행렬 검사, Bell-LaPadula MLS No-Read-Up 규칙, 그리고 Permissive vs Enforcing 모드 전환 동작을 대화형으로 확인할 수 있음:

<iframe src="../../assets/diagrams/selinux/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_selinux`)

- **파일 위치**: `labs/28-selinux/vuln_selinux.c`
- **노출 노드**: `/proc/vuln_selinux` (권한 `0666`)
- **지원 제어 명령**:
  - `echo 'mode permissive' > /proc/vuln_selinux`: Mode 0 설정 (Permissive 모드: AVC 감사 로그 생성 후 접근 허용)
  - `echo 'mode enforcing' > /proc/vuln_selinux`: Mode 1 설정 (Enforcing 모드: TE 및 MLS 위반 시 즉각 `-EACCES` 차단)
  - `echo 'test content' > /proc/vuln_selinux`: 인가된 정상 콘텐츠(`httpd_sys_content_t`) 읽기 테스트
  - `echo 'test shadow' > /proc/vuln_selinux`: 미인가 비밀번호 파일(`shadow_t`) 읽기 시도 (TE 위반)
  - `echo 'test mls' > /proc/vuln_selinux`: 하위 등급($s0$)에서 상위 등급($s1:c0$) 기밀 파일 읽기 시도 (MLS No-Read-Up 위반)
  - `echo 'test transition' > /proc/vuln_selinux`: 비인가 관리자 도메인(`unconfined_t`) 탈출 시도 (도메인 전이 위반)
  - `echo 'run_bench' > /proc/vuln_selinux`: 인커널 자체 종합 TE/MLS 정책 검증 및 성능 측정 루틴 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_selinux`)

- **파일 위치**: `labs/28-selinux/exploit.c`
- **동작 시나리오**:
  1. **환경 진단**: `/proc/self/attr/current`, `/sys/fs/selinux/enforce`, `/sys/kernel/security/lsm` 조회를 통한 SELinux 환경 확인.
  2. **Phase 1 (Permissive 모드 검증)**:
     - 정책 위반 요청(shadow 접근, MLS Read-up, 도메인 탈출)이 모두 허용(ALLOWED)되며 감사 로그만 남는 상태 확인.
  3. **Phase 2 (Enforcing 모드 검증)**:
     - 정상 콘텐츠 접근은 승인(GRANTED)됨을 확인.
     - shadow 접근, MLS Read-up, 도메인 탈출 시도가 커널에서 즉시 거부(`-EACCES`)됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_selinux`)

- **파일 위치**: `labs/28-selinux/test.sh` (루트fs 내 `/bin/test_selinux` 설치)
- **주요 검증 단계**:
  1. `securityfs` 및 `selinuxfs` 마운트 확인.
  2. `/proc/vuln_selinux` 타깃 노드 존재 및 상태 확인.
  3. 비특권 계정 `lab` (UID 1000)으로 `/bin/exploit_selinux` 실행.
  4. 커널 `dmesg`에서 표준 SELinux AVC 감사 레코드(`type=1400 audit(avc): denied ... permissive=0/1`) 검증.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/selinux.config`)
```ini
CONFIG_NET=y
CONFIG_INET=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE=256
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_LSM="landlock,lockdown,yama,selinux,bpf"
```

> [!NOTE]
> SELinux 소켓 후크 및 네트워크 라벨링 지원을 위해 `CONFIG_NET=y` 및 `CONFIG_INET=y`가 필수적임.

### 6.2 방어 비활성화 (`configs/features/selinux-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LSM="capability"
```

---

## 7. 검증 및 QEMU 실행 방법

### 7.1 루트 파일시스템 빌드
```bash
./scripts/build_rootfs.sh --arch arm64 --force
./scripts/build_rootfs.sh --arch x86_64 --force
```

### 7.2 커널 빌드
```bash
# ARM64 커널 빌드
./scripts/build_kernel.sh --arch arm64 --feature selinux

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature selinux
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-selinux/arch/arm64/boot/Image --test test_selinux --timeout 60

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-selinux/arch/x86/boot/bzImage --test test_selinux --timeout 60
```
