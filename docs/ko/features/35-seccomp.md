# Seccomp-BPF 시스템 콜 공격 표면 축소 및 샌드박싱

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**Seccomp (Secure Computing Mode with BPF Filters)**는 리눅스 프로세스가 호출할 수 있는 **시스템 콜(Syscall)의 집합을 암호학적/논리적으로 제한하여 커널 공격 표면(Attack Surface)을 획기적으로 축소하는 핵심 격리 기술**임.

현대 리눅스 커널은 450개 이상의 다양한 시스템 콜을 제공하지만, 대부분의 일반 데몬, 웹 서버(Nginx), 브라우저 렌더러, 컨테이너 워크로드는 정상 동작 중 30~50개 내외의 기본 시스템 콜만 사용함. 나머지 수백 개의 복잡한 시스템 콜은 잠재적인 커널 권한 상승 취약점(LPE)의 온상이 됨:

1. **커널 공격 표면 노출 위협**:
   - 공격자가 사용자 공간 애플리케이션의 메모리 오염(RCE)에 성공한 후, 취약한 커널 서브시스템(e.g., `ptrace`, `bpf`, `io_uring`, `unshare`, `keyctl`)을 호출하여 링-0 권한을 탈취하는 위협.
2. **컨테이너 탈출(Container Escape) 위협**:
   - 공유 커널 기반 컨테이너 환경에서 네임스페이스 조작 관련 시스템 콜(`setns`, `unshare`, `mount`)이나 시스템 제어 콜(`reboot`, `kexec_load`)을 호출하여 호스트 노드를 장악하는 위협.
3. **Seccomp-BPF 기반의 최소 권한 격리 (Least Privilege Sandboxing)**:
   - cBPF(Classic BPF) 필터 프로그램을 프로세스에 부착하여 시스템 콜 번호(`nr`), 아키텍처(`arch`), 인자(`args`)를 실시간 검사함.
   - 인가되지 않은 시스템 콜 호출 시 즉시 에러 반환(`SECCOMP_RET_ERRNO -EPERM`) 또는 프로세스 강제 종료(`SECCOMP_RET_KILL_PROCESS`)를 수행하여 익스플로잇 체인을 사전 차단함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. Seccomp-BPF 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/seccomp/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 특수 보안 시설의 '출입문 전자 금속 탐지기 및 차단 게이트'

Seccomp-BPF의 메커니즘은 **은행 금고 구역의 출입문 검색 시스템**과 정확히 일치함:

```
[ 비활성화 상태 (Disabled / 전통적 환경) ]
  방문객:   "나는 볼펜, 망치, 다이너마이트(450가지 모든 시스템 콜 도구)를 자유롭게 들고 금고실로 진입하겠다!"
  보안요원: "방문자 신분증(DAC/MAC 권한)만 있다면 모든 도구 반입을 막을 수 없음." (취약점 악용 가능)

[ Seccomp-BPF 화이트리스트 샌드박스 (Enforced) ]
  방문객:   "금고실 내부에서 write()와 read()로 서류만 작성하겠다고 서약(BPF 화이트리스트 등록)!"
  차단기:   "PR_SET_NO_NEW_PRIVS 활성화! 이후 어떠한 특권 상승도 불가하도록 하드웨어 래칫 잠금!"
  상황 1:   "정상 업무(read/write) 호출 -> 금속 탐지기 통과 -> SECCOMP_RET_ALLOW (정상 실행)."
  상황 2:   "갑자기 ptrace나 reboot 도구를 꺼내 휘두름 -> 탐지기 경보 작동!"
  조치:     "시스템 콜 디스패처 직전 차단! 핸들러 우회 후 즉각 -EPERM 반환 또는 강제 퇴장(SIGSYS 종료)!"
```

---

### 3. Seccomp 동작 모드 및 반환 액션 (Modes & Actions)

#### 1) 3가지 운영 모드

- **`SECCOMP_MODE_DISABLED` (0)**: 시스템 콜 필터링 없음. 커널의 모든 시스템 콜 허용.
- **`SECCOMP_MODE_STRICT` (1)**: 오직 `read()`, `write()`, `_exit()`, `sigreturn()` 4개 시스템 콜만 허용. 그 외 모든 호출 시 커널이 즉각 `SIGKILL` 전송.
- **`SECCOMP_MODE_FILTER` (2)**: 개발자가 정의한 cBPF 바이트코드 규칙을 통해 시스템 콜 번호 및 인자를 정밀하게 평가.

#### 2) Seccomp-BPF 주요 반환 액션 코드

| 액션 상수 | 16진수 값 | 설명 및 프로세스 동작 |
| :--- | :--- | :--- |
| `SECCOMP_RET_KILL_PROCESS` | `0x00000000` | 호출 즉시 전체 프로세스를 비정상 종료 (코어 덤프 생성 가능) |
| `SECCOMP_RET_KILL_THREAD` | `0x00000000` | 호출한 해당 스레드만 즉각 강제 종료 |
| `SECCOMP_RET_TRAP` | `0x00030000` | `SIGSYS` 시그널을 프로세스에 전달하여 자체 시그널 핸들러에서 트랩 처리 |
| `SECCOMP_RET_ERRNO` | `0x00050000` | 시스템 콜 핸들러 실행을 건너뛰고, 지정한 `errno`(e.g., `EPERM`)를 반환 |
| `SECCOMP_RET_USER_NOTIF` | `0x7fc00000` | 유저 공간 감시자(Supervisor) 파일 디스크립터로 시스템 콜 결정을 위임 |
| `SECCOMP_RET_LOG` | `0x7ffc0000` | 시스템 콜 실행은 허용하되, audit 로그에 위반 기록 남김 |
| `SECCOMP_RET_ALLOW` | `0x7fff0000` | 정상적인 시스템 콜 핸들러 호출 및 결과 반환 |

---

## 3. Kconfig 설정 및 부팅 파라미터 (Configuration)

### 1. Kconfig 프래그먼트

```ini
# configs/features/seccomp.config
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
```

### 2. 런타임 인터페이스 및 제어 플래그

| 제어 함수 / 노드 | 설명 |
| :--- | :--- |
| `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` | 비특권 프로세스가 SUID 바이너리를 실행하더라도 새로운 권한을 얻지 못하도록 잠금 (Seccomp-BPF 필터 적용의 필수 전제 조건) |
| `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` | 프로세스에 BPF 시스템 콜 필터 규칙을 주입하는 전용 시스템 콜 |
| `/proc/sys/kernel/seccomp/actions_avail` | 현재 커널에서 지원하는 Seccomp 반환 액션 리스트 조회 |
| `/proc/sys/kernel/seccomp/actions_logged` | 감사 로그에 기록할 Seccomp 액션 설정 |
| `/proc/[pid]/status` (`Seccomp: N`) | 대상 프로세스의 현재 Seccomp 모드 (`0`: 미적용, `1`: Strict, `2`: Filter) |

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

### 1. 테스트 시나리오 개요

- 비특권 계정(`lab`, UID 1000)으로 로그인.
- **Phase 1: Baseline (Disabled Mode)**:
  - 안전 시스템 콜(`write`) 및 위험 시스템 콜(`ptrace`)이 모두 제약 없이 호출됨.
- **Phase 2: Hardened (Target Driver BPF Filter Mode)**:
  - `/proc/vuln_seccomp`에 필터 정책 적용 후, 허용된 콜은 정상 처리되고 위험 콜은 `-EPERM`으로 차단됨.
- **Phase 3: Native Process Seccomp-BPF Injection**:
  - 자식 프로세스에서 `prctl(PR_SET_NO_NEW_PRIVS)` 설정 후 실제 BPF 필터를 로드함.
  - 화이트리스트된 `getpid()` 호출은 정상 성공.
  - 차단 목록에 포함된 `ptrace()` 호출 시 커널 BPF 엔진이 이를 가로채 `-1` 및 `errno = EPERM`을 반환함을 검증.

### 2. 듀얼 아키텍처 실측 실행 로그

=== "ARM64: Seccomp-BPF 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-seccomp/arch/arm64/boot/Image --test test_seccomp
    ```
    ```
    ================================================================
       Lab 35: Seccomp-BPF Syscall Sandbox Verification Suite        
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting process status Seccomp field...
    Seccomp:	0
    Seccomp_filters:	0

    [*] Step 2: Checking target driver at /proc/vuln_seccomp...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Seccomp PoC as user 'lab'...
    ================================================================
      Seccomp-BPF Syscall Filtering Sandbox PoC Exploit             
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
          Linux Seccomp-BPF Sandbox Status Report           
    ========================================================
    Current Seccomp Mode    : [2] BPF Filter (2: Fine-grained BPF Program)
    Caller Seccomp Status   : mode=0
    Total Syscalls Screened : 0
    Syscalls Allowed (RET_ALLOW) : 0
    Syscalls Denied (RET_ERRNO) : 0
    Syscalls Killed (RET_KILL)  : 0
    ========================================================

    [*] PHASE 1: Evaluating Baseline (Mode: Disabled - 0)
        -> Executing safe syscall... (GRANTED)
        -> Executing restricted attack syscall... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: BPF Filter - 2)
        -> Executing safe syscall (expecting GRANTED: ret = 0)... (GRANTED)
        -> Executing restricted syscall (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Testing Native In-Process Seccomp-BPF Filter
        [Child 1042] Setting PR_SET_NO_NEW_PRIVS...
        [Child 1042] Installing BPF syscall filter via prctl(PR_SET_SECCOMP)...
        [Child 1042] Filter installed successfully! Testing allowed syscall (getpid)...
        [Child 1042] getpid() succeeded: 1042
        [Child 1042] Attempting forbidden syscall (ptrace)...
        [Child 1042] [+] SUCCESS: ptrace was intercepted by Seccomp-BPF and returned -EPERM!
    [+] Native Seccomp-BPF test completed successfully!

    [+] Seccomp-BPF Verification Complete: Attack Surface Effectively Reduced!

    [*] Step 5: Inspecting kernel dmesg for Seccomp events:
    [    4.910201] seccomp: [ALLOW] Comm="exploit_seccomp" pid=1041 executed safe syscall -> SECCOMP_RET_ALLOW (ret = 0)
    [    4.910350] seccomp: [DENIED] Comm="exploit_seccomp" attempted restricted syscall -> SECCOMP_RET_ERRNO (-EPERM)
    ================================================================
       Lab 35 Test Complete: Verified Seccomp-BPF Syscall Filtering 
    ================================================================
    ```

=== "x86_64: Seccomp-BPF 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-seccomp/arch/x86/boot/bzImage --test test_seccomp
    ```
    ```
    ================================================================
       Lab 35: Seccomp-BPF Syscall Sandbox Verification Suite        
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting process status Seccomp field...
    Seccomp:	0
    Seccomp_filters:	0

    [*] Step 2: Checking target driver at /proc/vuln_seccomp...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Seccomp PoC as user 'lab'...
    ================================================================
      Seccomp-BPF Syscall Filtering Sandbox PoC Exploit             
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode: Disabled - 0)
        -> Executing safe syscall... (GRANTED)
        -> Executing restricted attack syscall... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: BPF Filter - 2)
        -> Executing safe syscall (expecting GRANTED: ret = 0)... (GRANTED)
        -> Executing restricted syscall (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Testing Native In-Process Seccomp-BPF Filter
        [Child 2055] Setting PR_SET_NO_NEW_PRIVS...
        [Child 2055] Installing BPF syscall filter via prctl(PR_SET_SECCOMP)...
        [Child 2055] Filter installed successfully! Testing allowed syscall (getpid)...
        [Child 2055] getpid() succeeded: 2055
        [Child 2055] Attempting forbidden syscall (ptrace)...
        [Child 2055] [+] SUCCESS: ptrace was intercepted by Seccomp-BPF and returned -EPERM!
    [+] Native Seccomp-BPF test completed successfully!

    [+] Seccomp-BPF Verification Complete: Attack Surface Effectively Reduced!

    [*] Step 5: Inspecting kernel dmesg for Seccomp events:
    [    8.210112] seccomp: [ALLOW] Comm="exploit_seccomp" pid=2054 executed safe syscall -> SECCOMP_RET_ALLOW (ret = 0)
    [    8.210255] seccomp: [DENIED] Comm="exploit_seccomp" attempted restricted syscall -> SECCOMP_RET_ERRNO (-EPERM)
    ================================================================
       Lab 35 Test Complete: Verified Seccomp-BPF Syscall Filtering 
    ================================================================
    ```

---

## 5. 성능 및 컨테이너 산업 표준 분석 (Performance & Industry Practice)

1. **실행 오버헤드 (Microscopic BPF Overhead)**:
   - cBPF 필터는 시스템 콜 진입 시 CPU 레지스터에 상주하는 `seccomp_data` 구조체를 즉시 평가함.
   - BPF JIT 컴파일러가 활성화된 최신 리눅스 커널에서는 필터 평가 오버헤드가 수십 나노초(ns) 수준(< 1~2%)에 불과하여 고성능 네트워크 및 웹 서버에 이상적임.
2. **Docker / Kubernetes 컨테이너 보안 표준**:
   - Docker의 기본 Seccomp 프로필은 위험한 44개 이상의 시스템 콜(`acct`, `add_key`, `bpf`, `clock_settime`, `kexec_load`, `ptrace`, `unshare` 등)을 사전에 차단함.
   - 이를 통해 90% 이상의 잠재적 제로데이 커널 권한 상승 취약점(CVE)이 컨테이너 내부에서 익스플로잇되기 전에 무력화됨.
3. **프로세스 영속적 적용 (Inheritance & Non-revocability)**:
   - Seccomp 필터는 `fork()`, `clone()`, `execve()` 후에도 자식 프로세스로 불변 상속되며, 한 번 적용된 필터는 프로세스 수명 주기 동안 제거하거나 비활성화할 수 없음.

---

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In contemporary cloud computing and containerized environments, the Linux kernel exposes more than 450 distinct system calls. However, typical web services, database daemons, or container microservices utilize only a modest subset of around 30 to 50 calls. The remaining 400 system calls—such as `ptrace`, `bpf`, `unshare`, and `keyctl`—represent an unnecessarily enormous attack surface. If a remote attacker achieves code execution inside a workload, they routinely exploit vulnerabilities in these obscure syscalls to achieve kernel Ring 0 privilege escalation. Today, we demonstrate the quintessential tool for attack surface reduction: **Seccomp-BPF**."

#### 2. Diagram & Architecture Walkthrough
> "Please direct your attention to our interactive architecture simulator. When an application initiates a syscall instruction—like `syscall` on x86_64 or `svc #0` on ARM64—the kernel traps the request inside `__secure_computing()` before dispatching it to the system call table. Seccomp packages the architecture, syscall number, and arguments into `struct seccomp_data` and executes an in-kernel BPF filter. If the system call matches our whitelist, it returns `SECCOMP_RET_ALLOW`. If an adversary invokes a prohibited call like `ptrace` or `reboot`, the engine bypasses the kernel handler entirely, returning an immediate `-EPERM` via `SECCOMP_RET_ERRNO` or terminating the hostile thread with `SECCOMP_RET_KILL_PROCESS`."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the progression across our test phases. In Phase 1, without filtering, restricted calls succeed unimpeded. In Phase 2, our target driver filters prohibited requests with `-EPERM`. In Phase 3, we execute a native in-process Seccomp-BPF filter using `prctl()`. We lock down the child process with `PR_SET_NO_NEW_PRIVS` and install a BPF program. Whitelisted calls like `getpid()` execute flawlessly. But the moment the child calls `ptrace()`, Seccomp intercepts the trap and forces a clean return value of `-1` with `errno` set to `EPERM`. The attack surface is completely neutralized without crashing the rest of the host."

#### 4. Key Takeaways & Production Advice
> "To conclude: Seccomp-BPF is the cornerstone of modern Linux sandboxing, underpinning container security in Docker, Kubernetes, and browser isolation in Chrome. By defining strict whitelist profiles and enforcing `PR_SET_NO_NEW_PRIVS`, organizations eliminate the vast majority of local privilege escalation vectors before vulnerabilities can ever be triggered."
