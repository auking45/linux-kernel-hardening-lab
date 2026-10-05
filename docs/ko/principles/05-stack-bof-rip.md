# 05. 클래식 버퍼 오버플로우와 RIP/PC 장악 (Buffer Overflow & Control Flow Hijack)

C 언어의 경계 검사 부재 결함으로 인해 입력 데이터가 스택 메모리의 한계를 넘어 **함수 포인터 및 복귀 주소(Return Address)를 변조하고 CPU 명령어 포인터(PC / RIP)를 탈취**하는 바이너리 익스플로잇의 기본 원리를 분석함. 임베디드 및 모바일 보안 표준인 **AArch64(ARM64)** 아키텍처를 기본(Default)으로 분석하며, **x86_64**와의 제어 흐름 탈취 메커니즘 및 하드웨어 방어 체계(ARM PAC/BTI vs Intel CET)를 심층 비교함.

---

## 1. 학습 목표 및 개요

- `memcpy()`, `strcpy()` 등 입력 길이를 검증하지 않는 메모리 복사 함수의 취약점 메커니즘을 규명함.
- AArch64와 x86_64의 스택 메모리 배치 차이에 따른 제어 흐름 탈취 표적(인접 함수 포인터 vs Saved RET)을 분석함.
- CPU의 간접 분기 명령어(`blr xN` / `ret`)를 통해 공격자가 의도한 비밀 관리자 함수(`unreachable_admin_shell`)로 제어권이 전이되는 과정을 추적함.
- 클래식 공격을 원천 무력화하기 위한 소프트웨어 3대 방어선(Stack Canary, NX/DEP, ASLR)을 분석함.
- 차세대 하드웨어 보안 기술인 **ARM PAC(Pointer Authentication)** 및 **BTI(Branch Target Identification)**와 Intel CET의 원리를 비교 학습함.

---

## 2. 인터랙티브 버퍼 오버플로우 & PC/RIP 장악 시뮬레이터

아래 다이어그램에서 4단계(정상 상태 ➔ 버퍼 초과 유입 ➔ 제어 포인터 변조 ➔ PC/RIP 탈취)를 거치며 메모리 바이트와 CPU 레지스터가 어떻게 전이되는지 확인 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/05-bof-rip.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 취약점 메커니즘: 경계 검사 없는 메모리 복사

```c
struct ServiceSession {
    char stack_buffer[64];
    void (*dispatch_handler)(void);
};

void vulnerable_service(const char *user_input, size_t input_len) {
    volatile struct ServiceSession session;
    session.dispatch_handler = normal_worker;

    /* 결함: stack_buffer 크기(64바이트)를 초과하는 입력 복사 허용 */
    memcpy((void *)session.stack_buffer, user_input, input_len);

    /* 간접 호출 시 변조된 함수 포인터로 점프 */
    session.dispatch_handler();
}
```

- 스택 메모리는 낮은 주소(SP)에서 높은 주소 방향으로 데이터를 순차 기록함.
- 따라서 `stack_buffer[0]`부터 쓰기 시작하여 64바이트를 초과하면, 그 바로 위 인접 오프셋에 위치한 **함수 포인터(`dispatch_handler`, 8바이트)**를 물리적으로 덮어쓰게 됨.

---

## 4. 아키텍처별 제어 흐름 탈취 메커니즘 비교

=== "AArch64 (ARM64 - 기본 타깃)"
    AArch64에서는 AAPCS64 규약상 현재 함수의 프레임 레코드(`X29`/`X30`)가 스택 프레임 최하단(`[sp]`)에 위치하므로, 단일 스택 프레임 내부에서는 인접 함수 포인터 변조를 통해 제어권을 장악함:

    ```
    [페이로드 구조 (총 72바이트)]
    [0x00 .. 0x3F] (64 바이트) : 'A' * 64 (버퍼 패딩)
    [0x40 .. 0x47] ( 8 바이트) : 0x0000000000400908 (unreachable_admin_shell 타깃 주소)
    ```

    ```mermaid
    sequenceDiagram
        autonumber
        actor Attacker as 공격자
        participant Stack as 스택 메모리 (Session)
        participant CPU as CPU 레지스터 (X0~X30 / PC)

        Attacker->>Stack: 72바이트 악성 페이로드 주입 (memcpy)
        Note over Stack: stack_buffer[64] ➔ 'A'*64<br/>dispatch_handler[8] ➔ 0x400908 (변조 완료!)
        CPU->>Stack: ldr x3, [sp, #64] (dispatch_handler 로드)
        CPU->>CPU: blr x3 (간접 분기 실행!)
        Note over CPU: PC = 0x400908 (<unreachable_admin_shell>)
        CPU->>Attacker: 비인가 관리자 쉘 실행 및 제어권 장악!
    ```

=== "x86_64 (AMD64 - 비교 타깃)"
    x86_64에서는 지역 변수 위 높은 주소에 Return Address(Saved RIP)가 직결되어 있어 `ret` 명령어 시점에 직접 명령어 포인터를 탈취함:

    ```
    [페이로드 구조 (총 80바이트)]
    [0x00 .. 0x3F] (64 바이트) : 'A' * 64 (버퍼 패딩)
    [0x40 .. 0x47] ( 8 바이트) : 'B' * 8  (Saved RBP / SFP)
    [0x48 .. 0x4F] ( 8 바이트) : 0x0000000000401156 (Saved RET 변조)
    ```

    - 함수 에필로그의 `ret` 명령어가 변조된 복귀 주소를 `RIP`로 POP하여 제어권을 탈취함.

---

## 5. 실습 소스 코드 및 제어 흐름 탈취 검증

- **실습 소스 코드**: [`bof_demo.c`](../../assets/labs/principles/05-bof-rip/bof_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/05-bof-rip/bof_demo.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/05-bof-rip/Makefile)

### 5.1 정상 실행 모드 (Normal Mode)

=== "AArch64 (기본 타깃)"
    ```bash
    cd labs/principles/05-bof-rip
    make run-normal
    ```

    ```
    === [1] Running Normal Mode [aarch64] ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./bof_demo
    ============================================================
     Classic Buffer Overflow & PC Hijacking Simulator [AArch64]
    ============================================================
    [*] Target Function unreachable_admin_shell : 0x400908
    [*] main() Function                         : 0x400bc8

    === [Mode 1: Normal In-Bounds Operation] ===
    [+] Sending safe payload (33 bytes) into 64-byte buffer.
    --- [Stack State Before Input Copy] ---
      session.stack_buffer[0] Address : 0x4000007feca8
      session.dispatch_handler Addr  : 0x4000007fece8 (points to: 0x4008e8)
      Saved Frame Pointer (FP/RBP)   : 0x4000007fec80
      Saved Return Address (LR/RIP)  : 0x400ae4
      Buffer to Handler Distance     : 64 bytes
    ---------------------------------------
    [+] vulnerable_service() invoking session.dispatch_handler()...
    [+] Normal worker executed safely. Workflow completed.
    ```

=== "x86_64 (비교 타깃)"
    ```bash
    cd labs/principles/05-bof-rip
    make ARCH=x86_64 run-normal
    ```

### 5.2 공격 실행 모드 (PC / RIP 탈취)

=== "AArch64 (기본 타깃)"
    ```bash
    make run-attack
    ```

    ```
    === [2] Running Control Flow Hijack Attack [aarch64] ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./bof_demo --attack
    ============================================================
     Classic Buffer Overflow & PC Hijacking Simulator [AArch64]
    ============================================================
    [*] Target Function unreachable_admin_shell : 0x400908
    [*] main() Function                         : 0x400bc8

    === [Mode 2: Buffer Overflow & Control Flow Hijack Attack] ===
    [+] Fabricated Exploit Payload (72 bytes):
        [0..63]  Buffer Padding   : 64 bytes of 'A' (0x41)
        [64..71] Hijacked Target  : 0x400908 (unreachable_admin_shell)

    [!] Delivering exploit payload into vulnerable_service()...
    --- [Stack State After Input Copy] ---
      session.dispatch_handler now   : 0x400908
    ---------------------------------------
    [+] vulnerable_service() invoking session.dispatch_handler()...

    ============================================================
     [!] CRITICAL SECURITY COMPROMISE: Control Flow Hijacked!
    ============================================================
     [★] CPU Instruction Pointer (RIP / PC) redirected to:
         unreachable_admin_shell() at 0x400908!
     [★] Attacker gained arbitrary code execution in target process.
    ============================================================
    ```

=== "x86_64 (비교 타깃)"
    ```bash
    make ARCH=x86_64 run-attack
    ```

    - 동일하게 인접 함수 포인터 변조를 통해 `unreachable_admin_shell`로 제어 흐름 탈취 검증 완료.

---

## 6. 현대 운영체제의 하드웨어 하드닝 방어 체계

현대 시스템에서는 단순 버퍼 오버플로우 공격을 저지하기 위해 컴파일러와 하드웨어 수준에서 다층 방어 체계를 가동함:

| 방어 기법 | AArch64 (ARMv8.3+ / ARMv8.5+) | x86_64 (Intel CET) | 핵심 원리 및 작동 메커니즘 |
| :--- | :--- | :--- | :--- |
| **반환 주소 보호** | **PAC (Pointer Authentication)**<br/>(`paciasp` / `autiasp`) | **CET Shadow Stack**<br/>(하드웨어 그림자 스택) | 하드웨어 키로 포인터를 암호화 서명하거나 별도 전용 스택에 RET를 격리 보관하여 변조 검출 |
| **간접 분기 보호** | **BTI (Branch Target Identification)**<br/>(`bti c`, `bti j`) | **CET IBT**<br/>(`ENDBR64` 착륙 패드) | 간접 분기 목적지가 사전 인가된 전용 착륙 패드 명령어가 아닐 경우 하드웨어 예외 발생 |
| **스택 카나리** | Stack Canary (`-fstack-protector`) | Stack Canary (`-fstack-protector`) | 프레임 경계에 랜덤 매직값을 삽입하여 변조 감지 시 즉각 커널 크래시 유발 |
| **메모리 실행 차단** | XN (Execute-Never / NX) | NX / DEP (No-Execute) | 스택/힙 데이터 영역의 코드 실행 권한 박탈 |
| **주소 무작위화** | ASLR & PIE | ASLR & PIE | 실행 시마다 세그먼트 기저 주소를 난수화하여 타깃 주소 고정 예측 차단 |

> [!TIP]
> 이제 본 기초 원리를 바탕으로, 실제 임베디드 및 엔터프라이즈 리눅스 시스템에서 발생한 실제 CVE 취약점과 커널 하드닝 방어 체계를 다루는 **[실전 공격 시나리오(Attack Scenarios)](../scenarios/index.md)**로 학습을 이어갈 수 있음.
