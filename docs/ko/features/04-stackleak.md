# CONFIG_GCC_PLUGIN_STACKLEAK: 커널 스택 데이터 소거 및 정보 누출 방어 메커니즘

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/stackleak/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="STACKLEAK Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 스택 잔여물 정보 누출 및 KASLR 무력화

- **스택 프레임 재사용과 데이터 잔류 현상**:
  - 리눅스 커널에서 프로세스(태스크)는 고정된 크기(x86_64 및 ARM64 기준 일반적으로 16KB, `THREAD_SIZE`)의 전용 커널 스택을 공유하여 사용함.
  - 시스템 콜이 종료되고 유저스페이스로 복귀(Syscall Exit)할 때, 커널은 스택 포인터(`RSP`/`SP`)만 원래 위치로 되돌릴 뿐 스택 메모리 내부의 데이터를 별도로 지우지 않음.
  - 직전 시스템 콜 실행 중 스택에 저장되었던 민감한 정보(커널 함수 포인터, 내부 구조체 주소, 암호화 키 파편 등)가 스택 메모리에 그대로 잔류함.
- **초기화되지 않은 스택 변수를 통한 정보 누출 (Uninitialized Stack Leak)**:
  - 이후 실행되는 다른 시스템 콜 내부에서 지역 변수나 버퍼 구조체가 명시적으로 초기화되지 않은 채 사용되는 경우, 직전 시스템 콜이 남긴 잔여 데이터가 해당 변수에 그대로 매핑됨.
  - 공격자가 해당 미초기화 변수를 `copy_to_user()` 등으로 읽어 유저 공간으로 복사할 경우, 커널 내부 텍스트 주소가 노출되어 **KASLR(Kernel Address Space Layout Randomization)**이 완전히 무력화됨.
  - 유출된 커널 베이스 주소는 ROP 체인 구성 및 권한 상승 Exploit의 결정적 시발점으로 악용됨.

### 1.2 직관적 실전 비유: 호텔 객실 청소 원리 (The Hotel Room Cleaning Metaphor)

- **비유 설명**:
  - 커널 스택은 손님들이 번갈아 묵는 **호텔 객실**에 해당함.
  - **하드닝 이전 (Base Kernel)**: 이전 투숙객(시스템 콜 A)이 퇴실할 때 서랍 속에 회사 기밀 문서(커널 함수 포인터)를 두고 나갔으나, 청소부가 방을 치우지 않음. 다음 투숙객(공격자의 시스템 콜 B)이 체크인하여 서랍(미초기화 스택)을 열어 기밀 문서를 그대로 훔쳐봄.
  - **STACKLEAK 하드닝 적용**: 손님이 방을 비우는 즉시 전문 하우스키핑 직원(`stackleak_erase`)이 투숙객이 사용한 영역(`lowest_stack` ~ 최상단)을 새 하얀 시트와 강력한 소독제(`0xffffffffffff4111` / `-0xBEEF` 포이즌)로 완벽하게 갈아치움. 다음 손님이 어떤 서랍을 열어도 소독제 냄새만 맡게 됨.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 GCC 컴파일러 플러그인 계측 (`stackleak_track_stack`)

- **최저 스택 수위(Lowest Watermark) 실시간 추적**:
  - `CONFIG_GCC_PLUGIN_STACKLEAK`는 GCC 컴파일러 플러그인(`scripts/gcc-plugins/stackleak_plugin.c`)을 통해 빌드 타임에 동작함.
  - 스택 프레임 크기가 `CONFIG_STACKLEAK_TRACK_MIN_SIZE`(기본값: 100바이트) 이상인 모든 커널 함수 진입부에 `stackleak_track_stack()` 호출 코드를 자동 삽입함:

    ```c
    void __used stackleak_track_stack(void)
    {
        unsigned long sp = current_stack_pointer;

        if (sp < current->lowest_stack &&
            sp >= stackleak_task_low_bound(current)) {
            current->lowest_stack = sp;
        }
    }
    ```

  - 프로세스의 `task_struct` 내에 정의된 `current->lowest_stack` 변수는 시스템 콜 실행 중 스택이 가장 깊게 도달한 최저 수위를 실시간으로 갱신함.

### 2.2 시스템 콜 복귀 시점의 소거 메커니즘 (`stackleak_erase`)

- **Syscall Exit 어셈블리 훅**:
  - 시스템 콜 처리가 완료되고 유저스페이스로 복귀하기 직전, 아키텍처별 진입 어셈블리(`arch/x86/entry/calling.h`, `arch/arm64/kernel/entry.S`)에서 `stackleak_erase()`를 호출함.
- **포이즈닝 소거 루틴 (`__stackleak_erase`)**:

  ```c
  static __always_inline void __stackleak_erase(bool on_task_stack)
  {
      const unsigned long task_stack_low = stackleak_task_low_bound(current);
      const unsigned long task_stack_high = stackleak_task_high_bound(current);
      unsigned long erase_low, erase_high;

      erase_low = stackleak_find_top_of_poison(task_stack_low,
                                               current->lowest_stack);
      erase_high = on_task_stack ? current_stack_pointer : task_stack_high;

      __stackleak_poison(erase_low, erase_high, STACKLEAK_POISON);

      /* 다음 시스템 콜을 위해 lowest_stack 수위를 최상단으로 리셋 */
      current->lowest_stack = task_stack_high;
  }
  ```

- **포이즌 값의 정의 (`STACKLEAK_POISON`)**:
  - `include/linux/stackleak.h`에 `#define STACKLEAK_POISON -0xBEEF`로 선언됨.
  - 64비트 아키텍처에서 부호 확장된 실제 16진수 값은 **`0xffffffffffff4111`**임.
  - 이 값은 가상 메모리 맵의 비정상 주소 영역(Canonical Hole)에 위치하여, 설령 포인터로 역참조되더라도 즉각적인 Page Fault를 유발하여 임의 코드 실행을 저지함.

### 2.3 커널 스택 고갈 (Stack Clash / Exhaustion) 방어

- `stackleak_task_low_bound(current)`는 커널 스택 하단의 `STACK_END_MAGIC`(0x57ac6e9d) 영역 직전을 가리킴.
- 비정상적인 재귀 호출이나 공격자의 대규모 스택 확장 시도가 발생할 경우, `stackleak_track_stack()`이 하단 경계를 초과하는 것을 감지하여 인접한 태스크 구조체 및 스레드 정보 영역 침범을 사전에 차단함.

---

## 3. 실습 환경 및 Exploit PoC (Hands-on Lab & Exploit PoC)

### 3.1 취약 타깃 드라이버 (`vuln_stackleak.c`)

- `/proc/vuln_stackleak` (mode 0666) 캐릭터 인터페이스 구현:
  - **Write 연산 (1단계: 스택 각인)**: 깊은 스택 프레임을 할당하고 고의로 민감한 커널 함수 포인터(`&vuln_stackleak_init`)를 스택에 적재 후 리턴.
  - **Read 연산 (2단계: 미초기화 스택 유출 시도)**: 스택에 512바이트 크기의 버퍼(`uninit_stack`)를 초기화하지 않고 선언한 뒤 유저스페이스로 `copy_to_user()` 수행.

### 3.2 Exploit PoC 실행 및 실측 결과 대조

```bash
# 1. Base 커널 (취약 환경) 실행
./scripts/run_lab.sh --arch x86_64 --feature stackleak-disabled --test test_stackleak

# 2. Hardened 커널 (STACKLEAK 활성화) 실행
./scripts/run_lab.sh --arch x86_64 --feature stackleak --test test_stackleak
```

=== "Base Kernel (Vulnerable: KASLR 정보 유출 성공)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - STACKLEAK Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] STACKLEAK Metric (/proc/<pid>/stack_depth): Not present (Disabled)

    [*] Step 1: Triggering kernel stack imprinting via write()...
        Write completed. Syscall exit returned to userspace.

    [*] Step 2: Reading uninitialized kernel stack via read()...
        Received 512 bytes of kernel stack memory.

    [*] Step 3: Analyzing leaked stack memory contents:
        Total Words Sampled:  64
        Poison Matches:       0 (STACKLEAK_POISON = 0xffffffffffff4111)
        Kernel Pointer Leaks: 32

    =========================================================
    [!] VULNERABILITY CONFIRMED: KASLR BYPASS VIA STACK LEAK
    [!] Leaked Kernel Function Pointer: 0xffffffff812356c0
    [!] Kernel stack was NOT poisoned on syscall exit.
    [!] Attackers can calculate kernel slide & defeat KASLR!
    =========================================================
    ```
    > **분석:** STACKLEAK이 비활성화된 기본 커널에서는 이전 시스템 콜이 기록한 커널 텍스트 주소가 그대로 유출되어 비특권 유저가 커널 주소 공간의 배치(KASLR Slide)를 완벽히 계산해냄.

=== "Hardened Kernel (Mitigated: STACKLEAK 방어 성공)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - STACKLEAK Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] STACKLEAK Metric (/proc/48/stack_depth): 672
    [*] STACKLEAK Runtime Sysctl (/proc/sys/kernel/stack_erasing): 1

    [*] Step 1: Triggering kernel stack imprinting via write()...
        Write completed. Syscall exit returned to userspace.

    [*] Step 2: Reading uninitialized kernel stack via read()...
        Received 512 bytes of kernel stack memory.

    [*] Step 3: Analyzing leaked stack memory contents:
        Total Words Sampled:  64
        Poison Matches:       64 (STACKLEAK_POISON = 0xffffffffffff4111)
        Kernel Pointer Leaks: 0

    =========================================================
    [+] DEFENSE ACTIVE: STACKLEAK MITIGATION VERIFIED!
    [+] Stack memory contains 64 STACKLEAK_POISON values (-0xBEEF).
    [+] All residual stack data was wiped on syscall exit.
    [+] Kernel pointer leakage completely blocked!
    =========================================================
    ```
    > **분석:** STACKLEAK 활성화 커널에서는 시스템 콜 복귀 시 스택이 `0xffffffffffff4111`(`-0xBEEF`)로 완전 소거되어 미초기화 변수를 통한 커널 포인터 유출이 원천 차단됨.

---

### 3.3 LKDTM 커널 자체 검증 테스트 (`STACKLEAK_ERASING`)

LKDTM의 `STACKLEAK_ERASING` 트리거를 통해 커널 내부에서 스택 소거 상태를 직접 진단함:

```bash
echo STACKLEAK_ERASING > /sys/kernel/debug/provoke-crash/DIRECT
```

- **Hardened 커널 커널 로그 (dmesg)**:
  ```text
  [    5.471970] lkdtm: Performing direct entry STACKLEAK_ERASING
  [    5.473268] lkdtm: stackleak stack usage:
  [    5.473268]   high offset: 168 bytes
  [    5.473268]   current:     344 bytes
  [    5.473268]   lowest:      944 bytes
  [    5.473268]   tracked:     944 bytes
  [    5.473268]   untracked:   128 bytes
  [    5.473268]   poisoned:    15136 bytes
  [    5.473268]   low offset:  8 bytes
  [    5.473530] lkdtm: OK: the rest of the thread stack is properly erased
  ```
- **Base 커널 커널 로그 (dmesg)**:
  ```text
  [   12.190412] lkdtm: Performing direct entry STACKLEAK_ERASING
  [   12.190981] XFAIL: stackleak is not enabled (CONFIG_GCC_PLUGIN_STACKLEAK=n)
  ```

---

## 4. 운영 및 런타임 제어 인터페이스 (Runtime Administration)

### 4.1 `/proc/<pid>/stack_depth` 메트릭

- `CONFIG_STACKLEAK_METRICS=y`가 켜진 경우 각 태스크의 최대 스택 소비량을 바이트 단위로 실시간 노출함.
- 시스템 관리자 및 개발자가 워크로드별 스택 사용량을 정량적으로 프로파일링할 수 있음.

### 4.2 `/proc/sys/kernel/stack_erasing` 런타임 토글

- `CONFIG_STACKLEAK_RUNTIME_DISABLE=y` 설정 시 런타임 제어 인터페이스 제공:
  - `1` (기본값): 시스템 콜 복귀 시 스택 소거 정상 수행.
  - `0`: 스택 소거 일시 비활성화 (벤치마크 및 긴급 성능 튜닝 시 활용).

---

## 5. 성능 및 오버헤드 분석 (Performance & Overhead)

- **CPU 연산 오버헤드**:
  - 단일 시스템 콜당 소거 비용은 스택 전체(16KB)가 아닌 **직전 시스템 콜이 실제로 사용한 깊이(`lowest_stack` ~ `task_stack_high`)**에만 비례함.
  - 대부분의 짧은 시스템 콜은 수백 바이트 미만의 스택만 소거하므로 전체 시스템 오버헤드는 **약 1% 수준**에 머무름.
- **메모리 공간 오버헤드**:
  - `task_struct` 내부에 포인터 필드 2개(`lowest_stack`, `prev_lowest_stack` 각 8바이트)만 추가되므로 메모리 오버헤드는 0에 수렴함.

---

## 6. 발표 대본 및 핵심 표현 (Presentation Script & Vocabulary)

### 6.1 프레젠테이션 발표 대본 (Korean & English)

```text
[1단계: Hook - 호텔 객실과 방치된 스택 데이터]
"호텔에 머물다 체크아웃할 때 서랍에 중요 문서를 깜빡 두고 나왔는데,
 청소부가 방을 치우지 않은 채 다음 손님을 받으면 어떤 일이 일어날까요?
 리눅스 커널의 기본 상태가 정확히 이렇습니다. 시스템 콜이 끝나도 스택에 남아 있던
 내부 커널 포인터는 그대로 방치되며, 다음 시스템 콜이 이를 읽어 유출하면 KASLR은 끝납니다."

"Imagine checking out of a hotel room leaving confidential documents in a nightstand drawer,
 and housekeeping never cleans the room before the next guest arrives.
 That is precisely the default state of the Linux kernel stack.
 When a system call exits, residual kernel pointers remain intact, allowing uninitialized
 reads in subsequent syscalls to completely shatter KASLR."

[2단계: Metaphor & Architecture - STACKLEAK의 포이즈닝 원리]
"CONFIG_GCC_PLUGIN_STACKLEAK은 이 문제를 완벽히 해결하는 강력한 하우스키핑 보안관입니다.
 함수가 실행될 때마다 lowest_stack 수위를 실시간으로 측정하고, 시스템 콜이 리턴하는 즉시
 사용되었던 모든 스택 영역을 0xffffffffffff4111, 즉 -0xBEEF라는 포이즌 값으로 소거합니다.
 다음 손님이 어떤 서랍을 열어보아도 오직 소독된 포이즌 값만 마주하게 됩니다."

"CONFIG_GCC_PLUGIN_STACKLEAK acts as an uncompromising automated housekeeping officer.
 It continuously tracks the lowest stack boundary during execution, and the moment a syscall exits,
 it wipes every single used byte with the poison value 0xffffffffffff4111, or -0xBEEF.
 Whatever uninitialized buffer a subsequent syscall inspects, it sees nothing but poison."

[3단계: Demo & Proof - 실측 QEMU 결과와 LKDTM 검증]
"실제 QEMU 실측 결과, 베이스라인 커널에서는 비특권 유저가 커널 함수 주소를 단번에 읽어내어
 KASLR을 우회했으나, 하드닝 커널에서는 64개의 스택 워드 전체가 완벽하게 포이즌 값으로 치환되어
 단 1비트의 주소 유출도 허용하지 않았습니다. LKDTM 자체 검증 또한 14KB 이상의 스택이
 완벽히 소거되었음을 공식 확인했습니다."

"In our live QEMU verification, an unprivileged user effortlessly extracted kernel pointers on the baseline kernel.
 But with STACKLEAK active, all 64 sampled stack words were reliably wiped with STACKLEAK_POISON,
 blocking the leak entirely. LKDTM kernel self-tests conclusively confirmed that the thread stack was properly erased."
```

### 6.2 핵심 프레젠테이션 영어 표현 (Key Presentation Phrases)

| 한국어 표현                              | 권장 영어 스피킹 표현                                              | 용례 및 발화 팁                               |
| :--------------------------------------- | :----------------------------------------------------------------- | :-------------------------------------------- |
| **"시스템 콜 복귀 시 스택을 소거하다"**  | _"erase residual kernel stack data upon syscall exit"_             | STACKLEAK의 핵심 동작 정의 시                 |
| **"최저 스택 수위를 추적하다"**          | _"track the lowest stack watermark in real-time"_                  | `lowest_stack` 추적 계측 원리 설명 시         |
| **"비정상 메모리 포이즌 값"**            | _"poison the stack with non-canonical values (-0xBEEF)"_           | `STACKLEAK_POISON` 상수의 방어적 가치 강조 시 |
| **"KASLR 우회를 원천 봉쇄하다"**         | _"preemptively thwart uninitialized stack infoleaks"_              | 공격 표면 차단 효과를 단언할 때               |
| **"사용된 스택 깊이에만 비례하는 비용"** | _"overhead driven strictly by stack depth rather than call count"_ | 1% 미만의 우수한 성능 효율성을 설명할 때      |
