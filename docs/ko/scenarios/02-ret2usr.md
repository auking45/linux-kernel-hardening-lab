# [Scenario 02] 커널 포인터 탈취 기반 ret2usr와 SMEP/PXN 하드웨어 실행 방어

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: 리눅스 커널 패킷 소켓 힙 오버플로우를 통한 함수 포인터 변조 (**CVE-2017-7308**)
    - **위협 벡터**: 유저 공간 Root(UID 0) 프로세스가 소켓 옵션(`packet_set_ring`) 취약점을 트리거하여 커널 내부 함수 포인터를 유저 공간 가상 주소(`0x00401337`)로 변조
    - **사이버-물리 피해**: 커널 특권(Ring 0)으로 유저 악성 쉘코드를 실행하여 워치독 스레드 강제 사살 및 관절 모터 전류 폭주(15A -> 85A) 유발
    - **1차 방어선**: 하드웨어 MMU 기반 **x86 CR4.SMEP (Supervisor Mode Execution Prevention)** 및 **ARM64 PTE_PXN (Privileged Execute-Never)**
    - **보완 방어선**: 유저 데이터 접근 차단 **SMAP/PAN** 및 페이지 테이블 분리 **KPTI (Kernel Page Table Isolation)**

---

## 1. 실제 커널 침해 사례 분석: CVE-2017-7308과 로봇 커널 권한 탈취

[Scenario 01](01-humanoid-bof.md)에서 공격자는 무선 데몬 버퍼 오버플로우(CVE-2026-76640)를 통해 유저 공간 Root(UID 0) 권한을 획득하였음. 그러나 리눅스 커널 하드닝(`Strict Devmem`, `Lockdown`, `Module Signing`)에 가로막혀 하드웨어 MMU 및 물리 레지스터 직접 제어가 차단된 상태임 ([5.3절 아키텍처 분석 참조](#53-post-exploitation-phase)).

이에 공격자는 유저 공간(Ring 3)에서 커널 공간(Ring 0)으로 권한을 상승(Privilege Escalation)시키기 위해 **리눅스 소켓 서브시스템의 취약점인 CVE-2017-7308**을 2차 피벗(Pivot)으로 익스플로잇함 ([6.1절 딥 다이브 참조](#deep-dive-smep-reg)).

```
[로봇 유저 공간 (Locomotion PC: UID 0 / Ring 3)]
               │ (setsockopt: PACKET_RX_RING 정수 오버플로우)
               ▼
[커널 AF_PACKET 소켓 핸들러: packet_set_ring] ──(힙 버퍼 슬랩 오염)──> [struct packet_sock]
                                                                              │ (함수 포인터 변조)
                                                                              ▼
                                                            [Ring 0 커널 워커의 유저 메모리 분기]
                                                                              │ (0x00401337 점프)
                                                                              ▼
                                                            [💥 워치독 무력화 & 모터 전류 85A 폭주]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **취약한 컴포넌트**: 리눅스 네트워크 서브시스템의 `net/packet/af_packet.c` 내 `packet_set_ring()` 함수.
- **결함 메커니즘**: `setsockopt()` 시스템 콜을 통해 패킷 링 버퍼 크기를 설정할 때 블록 크기 계산 과정에서 **정수 오버플로우(Integer Overflow)가 발생하여 슬랩 할당기(SLUB) 힙 버퍼의 범위를 벗어난 쓰기(Out-of-Bounds Write)**가 허용됨.
- **제어 흐름 탈취**: 공격자는 힙에 인접한 `struct packet_sock` 구조체의 함수 포인터(예: `prb_close_block` 또는 `packet_rcv`)를 자신이 유저 공간에 미리 할당해 둔 쉘코드 주소(`0x00401337`)로 덮어씀.
- **ret2usr 실행**: 커널이 해당 소켓으로 패킷을 수신하거나 링을 닫을 때, 커널 CPU(Ring 0)가 아무런 의심 없이 유저 공간 메모리(`0x00401337`)로 점프하여 악성 코드를 커널 최고 특권으로 실행하게 됨.

### 1.2 사이버-물리적 재난 분석 (Cyber-Physical Hazards)

커널 레벨(Ring 0) 제어권 장악은 유저 공간 루트 탈취와는 비교할 수 없는 물리적 재앙을 초래함:

- 🔴 **하드웨어 안전 워치독(Safety Watchdog) 강제 사살**: 커널 타이머 인터럽트 핸들러 및 워치독 킥(Kick) 루틴을 메모리에서 영구 제거하여 시스템 정지 시 페일세이프 록 발동을 무력화함.
- 🔴 **모터 인버터 게이트 드라이버 전류 폭주**: CAN/EtherCAT 버스를 거치지 않고 PCIe/GPIO 메모리 매핑 레지스터(MMIO)에 직접 쓰기를 수행하여 관절 모터 전류를 정격 15A에서 한계치인 85A로 급상승시킴.
- 🔴 **로봇 물리 기구부 파손 및 화재 위험**: 고전류 연속 인가로 인한 BLDC 모터 코일 소손, 감속기 기어 파손, 배터리 BMS 열폭주 유도함.

---

## 2. ret2usr 기술 메커니즘 및 메모리 경계 침범 원리

Return-to-User (ret2usr) 공격은 과거 리눅스 커널 익스플로잇의 가장 대표적인 기법으로, **커널 모드(Ring 0)와 유저 모드(Ring 3) 간의 메모리 실행 분리 부재**를 악용함 ([6.3절 하드웨어 예외 분석 참조](#deep-dive-pf-decode)).

### 2.1 가상 주소 공간 분할과 전통적 취약 구조

64비트 리눅스 시스템에서 프로세스의 가상 주소 공간은 다음과 같이 양분됨:

```
[ 0x0000000000000000 ~ 0x00007FFFFFFFFFFF ] : 유저 공간 (User Space / Ring 3)
   - 공격자가 mmap() 등을 통해 임의 주소에 쉘코드 배치 가능 (예: 0x00401337)
   - 페이지 테이블 엔트리(PTE)의 User/Supervisor 비트가 1 (User Access Allow)

─────────────────────── [TASK_SIZE 경계선] ───────────────────────

[ 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF ] : 커널 공간 (Kernel Space / Ring 0)
   - 커널 코드(.text), 데이터 구조체, 드라이버 MMIO 매핑
   - 페이지 테이블 엔트리(PTE)의 User/Supervisor 비트가 0 (Supervisor Only)
```

1. **과거 x86/ARM 커널의 치명적 설계 결함**:
   - CPU가 슈퍼바이저 모드(Ring 0)로 전환되면 주소 공간 전체에 대한 무제한 접근 권한을 획득함.
   - 이때 CPU 하드웨어는 Ring 0 상태에서 유저 공간 주소(`< TASK_SIZE`)의 코드를 읽어와 실행하는 행위를 제지하지 않았음.
2. **ret2usr 공격 진행 순서**:
   - 1단계: 공격자는 유저 공간 메모리(`0x00401337`)에 `commit_creds(prepare_kernel_cred(0))` 등의 권한 상승 기계어 코드를 배치함.
   - 2단계: 커널 내부의 함수 포인터를 `0x00401337`로 변조함.
   - 3단계: 커널 워커가 해당 함수 포인터를 간접 호출(`call *%rax`)함.
   - 4단계: CPU는 **Ring 0 권한을 그대로 유지한 채 유저 공간 메모리의 명령어를 실행**함.

---

## 3. 인터랙티브 다이어그램: 4단계 순차적 침투와 방어 흐름

프레임 내부 스크롤 간섭 없이, 전체 페이지 스크롤 흐름에 따라 각 침투 및 방어 단계를 순서대로 관찰 가능함.

### 3.1 [Phase 1] 정상 시스템 콜 디스패치 (Normal Syscall Dispatch)
- 유저 공간 프로세스가 `syscall`을 호출하여 커널 서비스 요청 시, Ring 0 커널 워커가 커널 메모리(`0xffffffff81...`) 내에서 정상 실행 후 `SYSRET`으로 복귀함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal Syscall Dispatch Diagram"></iframe>
</div>

### 3.2 [Phase 2] ret2usr 공격 분기 주입 (Return-to-User Hijack)
- 취약 커널(`CR4.SMEP=0`)에서 함수 포인터가 오염되어, Ring 0 CPU가 유저 메모리(`0x00401337`)의 악성 쉘코드로 점프하여 워치독을 살해하고 모터 전류를 85A로 폭주시키는 재난 발생함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Injection Diagram"></iframe>
</div>

### 3.3 [Phase 3] 하드웨어 MMU 트랩 발동 (SMEP / PXN Hardware Trap)
- 하드웨어 방어(`CR4.SMEP=1` / `PTE_PXN=1`) 활성화 환경에서 CPU가 Ring 0 상태로 User 페이지 분기 시도 즉시 MMU가 페이지 폴트(`#PF` Error Code `0x0011`)를 발동하여 0 클록 지연으로 차단함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Hardware Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] 페일세이프 E-Stop 및 관절 기구 록 (Fail-Safe Lockdown)
- 예외 발생 감지 즉시 하드웨어 안전 감시 릴레이가 모터 버스 전원을 0V로 즉각 차단하고 스프링 파킹 브레이크를 작동시켜 로봇을 물리적 전복 없이 안전 기립 록 상태로 보호함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Lockdown Diagram"></iframe>
</div>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-resize') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      if (iframe.contentWindow === e.source) {
        iframe.style.height = e.data.height + 'px';
      }
    });
  }
  if (e.data && e.data.type === 'diagram-theme-change') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      try {
        iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: e.data.theme }, '*');
      } catch(err){}
    });
  }
});

// MkDocs 테마 전환 감지 및 모든 iframe 다이어그램 동기화
function syncMkDocsThemeToIframes() {
  const scheme = document.body.getAttribute('data-md-color-scheme');
  const target = scheme === 'default' ? 'light' : 'dark';
  document.querySelectorAll('iframe').forEach(function(iframe) {
    try {
      iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: target }, '*');
    } catch(err){}
  });
}
const themeObserver = new MutationObserver(function(mutations) {
  mutations.forEach(function(mutation) {
    if (mutation.attributeName === 'data-md-color-scheme') {
      syncMkDocsThemeToIframes();
    }
  });
});
themeObserver.observe(document.body, { attributes: true, attributeFilter: ['data-md-color-scheme'] });
</script>

---

## 4. 하드닝 기술을 통한 계층적 방어 (Defense-in-Depth)

ret2usr 공격은 단일 기술이 아닌 **하드웨어 CPU 확장, 페이지 테이블 격리, 데이터 접근 차단의 다층 방어 체계**를 통해 완벽히 무력화됨:

| 방어 계층 | 보안 기술 | 적용 레이어 | 보호 대상 | 핵심 차단 메커니즘 |
| :--- | :--- | :--- | :--- | :--- |
| **1차 방어선** | **SMEP (x86) / PXN (ARM64)** ([6.1절](#deep-dive-smep-reg)) | CPU MMU 하드웨어 | 커널 코드 실행 흐름 | 슈퍼바이저 모드에서 유저 페이지 명령어 인출 시 `#PF` (0x0011) 트랩 유발 |
| **2차 방어선** | **SMAP (x86) / PAN (ARM64)** | CPU MMU 하드웨어 | 커널 데이터 접근 흐름 | 슈퍼바이저 모드에서 유저 공간 데이터 직접 읽기/쓰기 차단 (가짜 스택 피벗 차단) |
| **3차 방어선** | **KPTI (Kernel Page Table Isolation)** | 커널 가상 메모리 관리 | 페이지 테이블 구조 | 유저 모드와 커널 모드의 MMU 페이지 테이블을 분리하여 유저 주소 매핑 자체를 제거 |

### 4.1 [1차 방어선] SMEP (x86) 및 PXN (ARM64) 하드웨어 실행 방어

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **하드웨어 제어 레지스터 활성화**

        x86_64 커널 부팅 시 `arch/x86/kernel/cpu/common.c`에서 `CR4` 레지스터의 20번째 비트(`X86_CR4_SMEP`)를 세트함 ([6.1절 어셈블리 참조](#deep-dive-smep-reg)). ARM64는 스테이지 1 변환 테이블의 53번째 비트(`PTE_PXN`)를 1로 마킹함 ([6.2절 ARM64 분석 참조](#deep-dive-pxn-arm)).

    2.  **MMU 레벨 명령어 페치 감시**

        CPU가 슈퍼바이저 모드(CPL=0 / EL1)에서 동작하는 동안, MMU는 TLB 및 페이지 테이블의 $User/Supervisor$ 플래그를 실시간 비교 검증함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **0 클록 지연 하드웨어 트랩**

        유저 페이지(`U/S=1`)에서 단 1바이트의 명령어 인출 시도가 감지되는 즉시 CPU 하드웨어가 페이지 폴트(`#PF` 0x0011) 예외를 발생시켜 명령어 실행을 0%로 차단함.

    2.  **모든 형태의 순수 ret2usr 쉘코드 무력화**

        공격자가 유저 메모리에 아무리 정교한 쉘코드를 작성해 두더라도 커널 모드에서 해당 주소로 분기하는 순간 시스템 패닉이 유도됨.

</div>

### 4.2 [2차 보완 방어선] SMAP (Supervisor Mode Access Prevention) & ARM64 PAN

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **유저 데이터 읽기/쓰기 차단**

        SMEP가 실행(Instruction Fetch)만 차단하는 반면, SMAP(`CR4` Bit 21) 및 PAN(`PSTATE.PAN`)은 슈퍼바이저 모드에서 유저 메모리 데이터에 대한 무단 읽기 및 쓰기 접근까지 하드웨어 레벨에서 거부함.

    2.  **합법적 유저 복사만 명시적 허용**

        커널이 유저 데이터를 읽어야 할 때는 반드시 `stac` / `clac` 명령어(ARM64: `msr pan, #0`)를 감싼 안전한 `copy_from_user()` API를 통해서만 일시적으로 락을 해제함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **가짜 스택 피벗(Stack Pivot) 차단**

        공격자가 RSP를 유저 메모리의 ROP 체인으로 스위칭하려는 시도를 사전에 차단함.

    2.  **커널 함수 포인터 우회 변조 방어**

        커널 내부에서 유저 공간의 데이터 구조체를 직접 역참조하여 분기하려는 2차 우회 공격을 원천 봉쇄함.

</div>

### 4.3 [3차 구조적 방어선] KPTI (Kernel Page Table Isolation)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **페이지 테이블 물리적 이원화**

        유저 모드 실행용 페이지 테이블과 커널 모드 실행용 페이지 테이블을 완벽히 분리(`CR3` 전환)하여 운영함.

    2.  **커널 모드 진입 시 유저 매핑 마스킹**

        커널 공간에서 코드가 실행되는 동안 유저 공간 페이지 매핑 자체가 TLB 및 MMU 상에서 제거되어 있어 물리적으로 접근이 불가능함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **멜트다운(Meltdown) 및 부채널 공격 차단**

        유저 공간에서 투기적 실행(Speculative Execution)을 통해 커널 메모리를 훔쳐보는 하드웨어 부채널 공격을 방어함.

    2.  **SMEP 우회 공격 표면 최소화**

        페이지 테이블 레벨의 이중 격리를 통해 하드웨어 결함이나 레지스터 조작 공격에 대한 강력한 심층 방어막을 형성함.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (Hands-on Lab & Exploit PoC)

본 랩에서는 리눅스 소켓 취약점([CVE-2017-7308](https://nvd.nist.gov/vuln/detail/CVE-2017-7308))을 통한 커널 함수 포인터 변조 및 ret2usr 공격을 재현한 C 언어 시뮬레이터(`ret2usr_demo.c`)를 통해 취약 모드와 하드닝 모드의 동작 차이를 실측 검증함.

### 5.1 시뮬레이터 핵심 아키텍처 (`ret2usr_demo.c`)

- 실습 코드 위치: [`labs/scenarios/02-ret2usr/ret2usr_demo.c`](file:///home/auking45/repos/linux-kernel-hardening-lab/labs/scenarios/02-ret2usr/ret2usr_demo.c)
- **메모리 구조**: 커널 소켓 구조체(`struct mock_packet_sock`) 내부의 함수 포인터(`rx_handler`)가 공격자에 의해 유저 공간 쉘코드 함수(`user_malicious_shellcode`) 주소로 오염됨.
- **하드웨어 MMU 시뮬레이션**: x86 `CR4.SMEP` 및 ARM64 `PTE_PXN` 비트를 소프트웨어 MMU 디스패처로 모델링하여 명령어 페치 주소가 유저 가상 주소 영역인지를 검증함.

```c
/* labs/scenarios/02-ret2usr/ret2usr_demo.c 핵심 구조 */
typedef struct {
    uint32_t ring_buffer_size;
    uint32_t block_nr;
    void (*rx_handler)(void); // 공격자에 의해 유저 공간 주소로 변조되는 커널 함수 포인터
} mock_packet_sock_t;

// 유저 공간(Ring 3)에 위치한 공격자 악성 쉘코드
void user_malicious_shellcode(void) {
    // Ring 0 권한으로 실행되는 위험 텔레메트리: 워치독 사살 & 모터 전류 85A 폭주
}
```

---

### 5.2 공격 실행 및 물리적 재난 경고 로그 (Attack Execution & Cyber-Physical Disaster Logs)

SMEP 방어가 비활성화된 취약 커널(`CR4.SMEP=0`) 환경에서 소켓 함수 포인터 변조를 트리거했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (SMEP/PXN 방어선 부재 환경)
cd labs/scenarios/02-ret2usr && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 ⚡ Linux Kernel ret2usr & Hardware MMU Defense Lab (CVE-2017-7308) 
======================================================================

[MODE 2: RET2USR ATTACK WITHOUT SMEP (CR4.SMEP=0, PTE_PXN=0)]
[*] Simulating CVE-2017-7308: Heap out-of-bounds corrupting packet_sock...
    [!] Vulnerable pointer hijacked: sock->rx_handler = 0x5608f51ec290 (User Space)
[*] Dispatching socket RX packet in Kernel Context (CPL=0 / Ring 0)...
    [!] MMU Warning: CR4.SMEP=0. Instruction fetch from user space ALLOWED!

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Ring 0 CPU Running User Shellcode! 
======================================================================
  [*] Attacker payload executed with SUPERVISOR PRIVILEGE (Ring 0)!
  [*] Current CPU Execution Context: Ring 0 (CPL=0)
  [*] Code Location: User Space Virtual Address (0x5608f51ec290)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & KERNEL TAKEOVER] ---
  [🔴 PHYSICAL HAZARD] Hardware Safety Watchdog Thread: TERMINATED
  [🔴 PHYSICAL HAZARD] Joint Actuator Current Overload: 15.0 A -> 85.0 A (OVERHEAT)
  [🔴 PHYSICAL HAZARD] PCIe MMIO Motor Driver Registers: DIRECT WRITE ACCESS GRANTED
  [🔴 KERNEL PERSISTENCE] MMU Page Tables: Supervisor flags cleared across all user pages
```

> **사이버-물리 재난 분석:** SMEP가 없는 환경에서는 CPU가 커널 특권을 유지한 채 유저 쉘코드를 아무런 제약 없이 실행함. 그 결과 **워치독 스레드가 강제 종료되고 모터 인버터에 85A의 치명적 과전류가 인가되어 기구부 소손 및 영구 파손**이 유도됨.

---

### 5.3 익스플로잇 후속 공격: 커널 공간 장악 후 자행되는 2차 공격 (Post-Exploitation Phase) {: #53-post-exploitation-phase }

공격자가 ret2usr를 통해 커널 공간(Ring 0)의 제어권을 획득한 후 자행하는 영구 장악(Persistence) 및 하드웨어 파괴 시나리오는 다음과 같음:

1. **프로세스 자격 증명 탈취 및 완전 승격**:
   - `commit_creds(prepare_kernel_cred(0))`를 호출하여 현재 공격자 태스크의 `struct cred` 구조체 내 UID, GID, EUID를 모두 0으로 덮어씀.
2. **커널 보호 메커니즘 런타임 무력화**:
   - 커널 내부 변수인 `selinux_enforcing`을 0으로 덮어써 SELinux 정책을 무력화함.
   - `cr4` 레지스터의 비트를 조작하여 추가 보안 기능을 런타임에 해제함.
3. **스텔스 커널 루트킷(LKM Rootkit) 은닉 상주**:
   - 커널 내부 모듈 링크드 리스트(`modules`)에서 공격자 루트킷 노드를 분리(Unlink)하여 `lsmod` 명령어로 탐지되지 않는 스텔스 루트킷을 상주시킴.
4. **하드웨어 인터페이스 직접 장악**:
   - 운영체제 드라이버 계층을 완전히 우회하여 모터 인버터, 배터리 관리 시스템(BMS), LIDAR 센서의 MMIO 물리 레지스터를 직접 조작함.

---

### 5.4 방어 활성화 실측: 하드웨어 MMU 트랩 및 페일세이프 록

하드웨어 MMU 보안(`CR4.SMEP=1` / `PTE_PXN=1`)이 활성화된 환경에서 동일한 ret2usr 공격을 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 하드닝 모드 실행 (SMEP/PXN 활성화 환경)
cd labs/scenarios/02-ret2usr && make run-hardened
```

**방어 성공 텔레메트리 출력 로그**:
```text
======================================================================
 ⚡ Linux Kernel ret2usr & Hardware MMU Defense Lab (CVE-2017-7308) 
======================================================================

[MODE 3: RET2USR ATTACK WITH HARDENED MMU (CR4.SMEP=1, PTE_PXN=1)]
[*] Simulating CVE-2017-7308: Heap out-of-bounds corrupting packet_sock...
    [!] Vulnerable pointer hijacked: sock->rx_handler = 0x5608f51ec290 (User Space)
[*] Dispatching socket RX packet in Kernel Context (CPL=0 / Ring 0)...
    [*] Hardware MMU Intercept: Validating instruction fetch address against User/Supervisor bit...

======================================================================
 [🛡️ HARDWARE MMU TRAP DETONATED] Page Fault (#PF) Exception! 
======================================================================
  [!] VIOLATION DETECTED: Supervisor CPU (Ring 0) attempted instruction fetch from User Page!
  [!] Hardware Registers:
      CR4.SMEP = 1 (Enabled) | PTE_PXN = 1 (Active)
      Target Address = 0x5608f51ec290 (< TASK_SIZE)
      Page Fault Error Code = 0x0011 (Supervisor Instruction Fetch Protection Violation)
  [!] Execution blocked: 0 instructions executed in user space. Arbitrary code execution: 0%
  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured!
```

> **방어 결론:** 함수 포인터가 유저 공간으로 변조되었음에도 불구하고, CPU 하드웨어 MMU가 명령어 인출 첫 클록에서 **SMEP 위반(`#PF` Error Code 0x0011)을 감지하고 즉각 예외를 발생**시킴. 쉘코드는 단 1바이트도 실행되지 못하였으며, 세이프티 릴레이가 작동하여 로봇이 안전 기립 록 상태로 보존됨.

---

## 6. 엔지니어링 딥 다이브 (Engineering Deep Dive)

이 절에서는 시스템 엔지니어 및 하드웨어 아키텍트를 위한 저수준 레지스터 제어 및 예외 디코딩 상세 명세를 제공함.

### 6.1 x86_64 CR4.SMEP 제어 레지스터 및 부팅 활성화 어셈블리 {: #deep-dive-smep-reg }

Intel 및 AMD x86_64 아키텍처에서 SMEP는 `CR4` 컨트롤 레지스터의 20번째 비트에 위치함:

```nasm
; [x86_64] 커널 부팅 초기화 루틴 (arch/x86/kernel/cpu/common.c)
movq    %cr4, %rax            ; 현재 CR4 레지스터 값 읽기
btsq    $20, %rax             ; Bit 20 (X86_CR4_SMEP) 세트 (1 << 20 = 0x00100000)
movq    %rax, %cr4            ; CR4 레지스터 갱신 -> SMEP 즉시 하드웨어 활성화
```

- 만약 CPL=0(Ring 0) 상태인 CPU가 유저 권한 비트($U/S = 1$)가 설정된 선형 가상 주소로부터 명령어를 읽어오려 하면, MMU는 즉시 벡터 14번 예외인 **`#PF`(Page Fault)**를 발생시킴.
- 🔗 [상세 기술 명세서: 09. SMEP & PXN 하드웨어 실행 방어 분석](../../features/09-smep-pxn.md)

### 6.2 ARM64 Stage 1 변환 테이블 및 PTE_PXN (Bit 53) {: #deep-dive-pxn-arm }

ARMv8-A/ARMv9-A AArch64 아키텍처에서는 Stage 1 Translation Table Entry의 **Bit 53 (`PTE_PXN`: Privileged Execute-Never)**을 사용함:

```text
[ARM64 64-bit Stage 1 Translation Block/Page Descriptor]
63      59 58 54 53  52 51                                          12 11   2 1 0
+---------+-----+---+---+--------------------------------------------+-----+---+-+
| Ignored | ... |PXN|UXN| Output Physical Address (Bits 47:12)       | AP  |...|1|
+---------+-----+---+---+--------------------------------------------+-----+---+-+
                 │
                 └──> Bit 53 = 1 : EL1(슈퍼바이저)에서 이 페이지의 코드 실행 절대 불가!
```

- 유저 공간 페이지 매핑 시 커널은 `PTE_PXN` 비트를 항상 1로 설정함.
- EL1 모드에서 해당 페이지를 실행하려 시도하면 MMU가 **Instruction Abort Exception**(`ESR_EL1` Exception Class `0x21`: Instruction Abort taken without a change in Exception level)을 발생시킴.

### 6.3 하드웨어 `#PF` 에러 코드 0x0011 비트필드 분석 {: #deep-dive-pf-decode }

x86 하드웨어가 `#PF` 발생 시 스택에 푸시하는 32비트 에러 코드의 상세 구조는 다음과 같음:

| 비트 위치 | 플래그 이름 | 설정 값 | 기술적 의미 |
| :--- | :--- | :--- | :--- |
| **Bit 0** | **P (Present)** | `1` | 페이지가 물리 메모리에 매핑되어 있음 (보호 정책 위반) |
| **Bit 1** | **W/R (Write/Read)** | `0` | 읽기 또는 인스트럭션 페치 접근 |
| **Bit 2** | **U/S (User/Supervisor)** | `0` | **슈퍼바이저 모드(Ring 0)**에서 접근 중 위반 발생 |
| **Bit 3** | **RSVD (Reserved Bit)** | `0` | 예약된 비트 위반 없음 |
| **Bit 4** | **I/D (Instruction Fetch)** | `1` | **명령어 인출(Execute) 시도** 중 위반 발생 (SMEP 시그니처!) |

- **결합 값**: `0x0001` (Bit 0) | `0x0010` (Bit 4) = **`0x0011`**.
- 리눅스 커널 페이지 폴트 핸들러(`arch/x86/mm/fault.c`)는 에러 코드가 `0x0011`인 경우 이를 전형적인 악성 ret2usr 시도로 판단하고 치명적 커널 오류(`Oops: 0011 [#1] PREEMPT SMP`)를 발생시켜 즉각 시스템을 안전 종료함.

### 6.4 공격자의 진화: ret2usr에서 kROP (Kernel ROP)로의 전환 {: #deep-dive-krop-pivot }

- SMEP/PXN이 기본 탑재되면서 유저 공간 쉘코드를 직접 실행하는 고전적 ret2usr 공격은 100% 무력화되었음.
- 이에 대항하여 공격자들은 **커널 내부(.text)에 이미 존재하는 합법적 명령어 조각(Gadget)들을 체이닝하는 kROP (Kernel Return-Oriented Programming)** 기법으로 진화함.
- 커널 ROP 체인을 구성하려면 커널 함수의 메모리 적재 주소를 알아내야 하므로, 이를 방어하기 위해 **KASLR (`CONFIG_RANDOMIZE_BASE`)**, **FG-KASLR**, **kCFI**가 필수적인 다음 방어선으로 대두됨.
- 🔗 [커널 주소 공간 난수화: 05. KASLR 명세서](../../features/05-kaslr.md)
- 🔗 [제어 흐름 무결성: 13. Clang kCFI 명세서](../../features/13-kcfi.md)

---

## 7. 참고 문헌 및 공식 CVE 보안 공시 (External Advisories & References)

<div class="grid cards vertical" markdown>

-   __📌 공식 CVE 데이터베이스__

    ---

    1.  **CVE-2017-7308**

        Linux Kernel `packet_set_ring` AF_PACKET Heap Out-of-Bounds Privilege Escalation

    2.  **CVE-2022-25636**

        Linux Kernel `netfilter` (nf_tables) Heap Out-of-Bounds Write leading to Local Privilege Escalation

-   __🔬 보안 연구 및 기술 분석 보고서__

    ---

    1.  **Andrey Konovalov (Google Project Zero, 2017)**

        *"Exploiting CVE-2017-7308: A Linux Kernel Socket Vulnerability Deep Dive"*

    2.  **Vitaly Nikolenko (2018)**

        *"Modern Linux Kernel Exploitation: Bypassing SMEP/SMAP using kROP and Page Table Manipulation"*

    3.  **Intel 64 and IA-32 Architectures Software Developer's Manual**

        Volume 3A: System Programming Guide - Section 4.6 (Supervisor-Mode Execution Prevention)

-   __🛡️ 리눅스 커널 하드닝 & 하드웨어 표준__

    ---

    1.  **Linux Kernel Hardening Project**

        [Hardware-assisted Memory Protection (SMEP & SMAP)](https://kernsec.org/)

    2.  **ARM Architecture Reference Manual (ARMv8/v9-A)**

        Section D5: Memory System Architecture - Privileged Execute-Never (PXN)

    3.  **Kernel Documentation (x86)**

        `Documentation/arch/x86/smep.rst` - Supervisor Mode Execution Prevention Mechanics

</div>
