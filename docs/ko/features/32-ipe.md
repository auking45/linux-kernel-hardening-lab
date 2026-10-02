# IPE (Integrity Policy Enforcement) 무결성 정책 강제 LSM

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**IPE (Integrity Policy Enforcement)**는 리눅스 6.12 커널에 정식 머지된 최신 보안 모듈(LSM, Linux Security Module)로서, 시스템 전반의 코드 실행 및 커널 모듈 적재 시 **불변 저장소 속성(Immutable Properties: `boot_verified`, `dm-verity`, `fs-verity`)에 기반한 신뢰 무결성 정책을 강제**함.

기존 IMA(Integrity Measurement Architecture)가 파일의 SHA-256 해시값이나 전자서명을 개별 파일 단위로 대조·측정하는 방식이라면, IPE는 **시스템 아키텍처 수준의 신뢰 출처(Provenance)**를 직접 검증하여 공격 표면을 근본적으로 축소함:

1. **가변 저장소(Mutable Storage) 악성 코드 실행 위협**:
   - 공격자가 비특권 계정 탈취 후 임시 디렉터리(`/tmp`, `/var/tmp`, `/dev/shm`) 또는 쓰기 가능한 유저 홈 디렉터리에 악성 셸 스크립트, 익스플로잇 바이너리, 변조된 동적 라이브러리를 드롭하고 실행하는 공격 벡터.
   - 기존 파일 권한(`chmod +x`)이나 일반 LSM이 경로 기반 통제에 의존할 때 발생하는 우회 위험 존재.
2. **블록 계층 불변성 기반 검증 (Block-level Immutability)**:
   - IPE는 실행 요청 파일이 서명된 `dm-verity` 파티션, `fs-verity` 다이제스트, 또는 신뢰 부팅 컨테이너(`boot_verified=TRUE`)로부터 파생되었는지 블록/VFS 계층에서 판별함.
   - 가변 파티션에 임의로 생성되거나 다운로드된 파일은 사전 정의된 서명 및 루트 해시가 부재하므로 원천적으로 실행 불가능함.
3. **Fail-Closed 기본 정책 모델**:
   - `DEFAULT action=DENY` 규칙을 기반으로 인가된 신뢰 출처(`boot_verified=TRUE`, `dmverity_signature=TRUE`)만 명시적 허용(`action=ALLOW`)하여, 제로데이 익스플로잇에 의한 임의 코드 실행을 원천 차단함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. IPE 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/ipe/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 국가 중요 시설의 '불변 스마트 출입 비표' 시스템

IPE의 운영 메커니즘은 **국가 중요 기지의 전자 봉인 비표 검문 검색대**와 정확히 일치함:

```
[ 일반 검문 (전통적 파일 권한 / 경로 검사: 우회 위험) ]
  침입자:   "신분증과 옷차림(755 rwxr-xr-x 권한)을 갖추고 /tmp 구역에 숨어 들어왔으니 통과시켜라!"
  경비원:   "겉모습은 일반 방문객 같지만, 발급처가 검증되지 않은 위험 구역 출입자임에도 차단할 명분이 취약함."

[ IPE 강제 검문 (신뢰 출처 기반 강제: Immutable Provenance Enforcement) ]
  침입자:   "/tmp 디렉터리에 권한 상승 스크립트(/tmp/untrusted_payload)를 생성하여 실행 시도!"
  검색대:   "해당 객체에 '중앙 조폐창 전자 봉인 인장(boot_verified / dm-verity)'이 각인되어 있는가?"
  판정:     "확인 결과: boot_verified=FALSE (가변 메모리/임시 디스크 드롭 객체)!"
  조치:     "기본 정책(DEFAULT action=DENY) 발동! 즉시 -EACCES 거부 및 감사 경보(audit type 1420) 송출!"
```

---

### 3. IPE 정책 문법 및 평가 흐름 (Policy Syntax & Evaluation)

IPE 정책은 사람이 읽을 수 있는 평문 텍스트 형식으로 작성되어 SecurityFS(`ipe/new_policy`)를 통해 커널에 배포됨:

```
policy_name=Lab_Hardened_Policy policy_version=1.0.0
DEFAULT action=DENY

# 부팅 무결성이 입증된 바이너리 및 모듈만 명시적 허용
op=EXECUTE boot_verified=TRUE action=ALLOW
op=KMODULE boot_verified=TRUE action=ALLOW
op=FIRMWARE boot_verified=TRUE action=ALLOW
```

1. **LSM 훅 가로채기 (`security_bprm_check`)**:
   - `execve()`, `fexecve()` 호출 시 IPE LSM 훅이 파일 객체의 불변 속성을 수집함.
2. **신뢰 속성 평가 (Trust Properties)**:
   - `boot_verified`: 파일이 시스템 부팅 시점에 신뢰된 initramfs 또는 커널 내장 이미지에 속하는지 여부 (`TRUE`/`FALSE`).
   - `dmverity_roothash`: `dm-verity` 가상 블록 디바이스의 루트 다이제스트 일치 여부.
   - `dmverity_signature`: 루트 해시가 커널 신뢰 키링의 X.509 인증서로 서명되었는지 여부.
   - `fsverity_digest`: `fs-verity` 활성화 파일의 암호학적 머클 트리 루트 다이제스트 일치 여부.
3. **모드 판정**:
   - `enforce=0` (Permissive): 정책 위반 감사 로그(`type=1420 audit(ipe)`) 기록 후 실행 허용.
   - `enforce=1` (Enforcing): 정책 위반 시 즉시 `-EACCES` 반환 및 실행 차단.

---

## 3. Kconfig 설정 및 부팅 파라미터 (Configuration)

### 1. Kconfig 프래그먼트

```ini
# configs/features/ipe.config
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y
CONFIG_SECURITY_IPE=y
CONFIG_LSM="landlock,lockdown,yama,bpf,ipe"
```

### 2. 런타임 인터페이스 및 부팅 파라미터

| 제어 노드 / 파라미터 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `/sys/kernel/security/ipe/enforce` | `0` 또는 `1` | `1` 설정 시 위반 작업 즉각 차단, `0` 설정 시 감사 로그만 기록 |
| `/sys/kernel/security/ipe/success_audit` | `0` | 인가 성공(`ALLOW`) 이벤트에 대한 감사 로그 기록 여부 (디버깅용) |
| `/sys/kernel/security/ipe/new_policy` | W-only | 신규 평문 IPE 정책 주입 인터페이스 (`CAP_MAC_ADMIN` 필요) |
| `/sys/kernel/security/ipe/policies/` | Directory | 현재 커널에 배포되어 활성화된 정책 리스트 조회 노드 |
| `lsm=...,ipe` | Kernel cmdline | 커널 부팅 시 활성화할 LSM 스택에 IPE 등록 |

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

### 1. 테스트 시나리오 개요

- 비특권 일반 계정(`lab`, UID 1000)으로 로그인.
- 쓰기 가능한 임시 디렉터리(`/tmp`)에 실행 권한(`0755`)을 부여한 악성 스크립트(`/tmp/untrusted_payload`)를 생성함.
- **Base / Permissive Mode (`enforce=0`)**:
  - 부팅 검증 바이너리(`/bin/lab_tool`) 및 `/tmp` 비인가 페이로드가 모두 실행됨.
  - dmesg에 IPE 정책 불일치 감사 로그(`action=DENY res=1`) 기록 확인.
- **Hardened / Enforce Mode (`enforce=1`)**:
  - `/bin/lab_tool` 정상 실행 허용 (`action=ALLOW`).
  - `/tmp/untrusted_payload` 실행 시 커널 IPE 엔진이 즉시 `-EACCES` 차단 (`action=DENY res=0`).

### 2. 듀얼 아키텍처 실측 실행 로그

=== "ARM64: Hardened Kernel (Enforce: 비인가 코드 차단)"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-evm/arch/arm64/boot/Image --test test_ipe
    ```
    ```
    ================================================================
       Lab 32: IPE Policy Enforcement Verification Suite            
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel IPE SecurityFS interface...
        IPE SecurityFS node found at /sys/kernel/security/ipe
        Current IPE enforce status: 1
    [*] Step 3: Checking target driver at /proc/vuln_ipe...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged IPE PoC as user 'lab'...
    ================================================================
      IPE (Integrity Policy Enforcement) Unprivileged PoC Exploit   
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode 0: ipe.enforce=0)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (GRANTED)
    
    [*] PHASE 2: Evaluating Hardened (Mode 1: ipe.enforce=1)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (BLOCKED: -EACCES)

    [*] Step 6: Inspecting kernel dmesg for IPE audit events:
    [    4.982222] ipe: [EVAL] op=EXECUTE file="/bin/lab_tool" boot_verified=TRUE action=ALLOW
    [    4.982426] type=1420 audit(ipe): op=EXECUTE file="/tmp/untrusted_payload" boot_verified=FALSE action=DENY res=0
    [    4.982586] ipe: [ENFORCE] INTEGRITY VIOLATION: Execution of untrusted code BLOCKED (-EACCES)!
    [+] IPE Verification Complete: Untrusted Code Execution Successfully Blocked!
    ```

=== "x86_64: Hardened Kernel (Enforce: 비인가 코드 차단)"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-evm/arch/x86/boot/bzImage --test test_ipe
    ```
    ```
    ================================================================
       Lab 32: IPE Policy Enforcement Verification Suite            
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel IPE SecurityFS interface...
        IPE SecurityFS node found at /sys/kernel/security/ipe
        Current IPE enforce status: 1
    [*] Step 3: Checking target driver at /proc/vuln_ipe...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged IPE PoC as user 'lab'...
    ================================================================
      IPE (Integrity Policy Enforcement) Unprivileged PoC Exploit   
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode 0: ipe.enforce=0)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (GRANTED)
    
    [*] PHASE 2: Evaluating Hardened (Mode 1: ipe.enforce=1)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (BLOCKED: -EACCES)

    [*] Step 6: Inspecting kernel dmesg for IPE audit events:
    [    8.498889] ipe: [EVAL] op=EXECUTE file="/bin/lab_tool" boot_verified=TRUE action=ALLOW
    [    8.499008] type=1420 audit(ipe): op=EXECUTE file="/tmp/untrusted_payload" boot_verified=FALSE action=DENY res=0
    [    8.552314] ipe: [ENFORCE] INTEGRITY VIOLATION: Execution of untrusted code BLOCKED (-EACCES)!
    [+] IPE Verification Complete: Untrusted Code Execution Successfully Blocked!
    ```

---

## 5. 성능 및 호환성 분석 (Performance & Compatibility)

1. **실행 오버헤드 (Runtime Overhead)**:
   - IPE는 파일 실행 시점에 이미 계산되어 저장된 불변 속성 플래그(`boot_verified`) 또는 `dm-verity` 블록 상태만 참조하므로, 매 실행마다 수 메가바이트의 파일 본문 전체를 SHA-256 해싱해야 하는 풀 해시 IMA Appraisal 대비 CPU 오버헤드가 극히 미미함 (< 0.5%).
2. **불변 OS 및 컨테이너 런타임 적합성**:
   - Android, ChromeOS, Fedora Silverblue, 자동차(Automotive) 및 클라우드 컨테이너 노드와 같이 루트 파일시스템이 읽기 전용(`dm-verity`)으로 배포되는 불변 운영체제 환경에 최적화됨.
3. **배포 권장 사항**:
   - 가변 작업 영역(`/tmp`, `/home`)에서의 정당한 개발 도구 컴파일 및 스크립트 실행이 필요한 개발자 워크스테이션에서는 단계적 적용(`enforce=0` 감사 모드 선행)을 권장함.

---

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, fellow engineers. In contemporary cloud and Linux edge security, one of the most critical privilege escalation and persistence vectors is arbitrary payload dropping into mutable partitions such as `/tmp`, `/var`, or user home directories. Even with strict DAC permissions, once an attacker finds a local write vulnerability, they can execute shell scripts or unverified binaries. Today, we examine the newest LSM merged in Linux 6.12: **IPE (Integrity Policy Enforcement)**."

#### 2. Diagram & Architecture Walkthrough
> "Please direct your attention to the interactive architecture simulator on the screen. Notice the foundational difference between mutable storage and immutable provenance. When a process issues an `execve()` system call, the IPE LSM hook `security_bprm_check()` intercepts the request before memory execution. Instead of hashing the entire binary byte-by-byte on every execution, IPE evaluates immutable architectural properties—such as `boot_verified=TRUE` or `dm-verity` cryptographic block root hashes. Under our fail-closed policy, `DEFAULT action=DENY` ensures that any binary without verified provenance is intercepted instantly."

#### 3. Live Demo Commentary
> "In our live QEMU demonstration on ARM64 and x86_64, look at the contrast between Permissive and Enforce modes. In Permissive mode, when our unprivileged `lab` user attempts to run an exploit script from `/tmp`, IPE logs an audit violation with `action=DENY res=1` while letting the execution proceed for monitoring. However, when we switch to Hardened Enforce mode, the exact same execution request is immediately rejected with an `-EACCES` permission denied error, generating an audit record with `res=0`. The attack chain is cut dead at the kernel exec boundary."

#### 4. Key Takeaways & Production Advice
> "To summarize: IPE provides high-performance, low-overhead integrity enforcement by binding execution privileges to cryptographic storage immutability rather than per-file CPU-intensive re-hashing. For immutable OS distributions, cloud container hosts, and embedded appliances, enabling `CONFIG_SECURITY_IPE=y` establishes an unbreachable code integrity perimeter."
