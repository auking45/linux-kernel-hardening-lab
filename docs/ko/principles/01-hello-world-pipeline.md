# 01. Hello World의 탄생과 실행 파이프라인 (Program Lifecycle)

모든 시스템 프로그래밍과 보안 학습의 출발점인 `"Hello World"` 프로그램이 작성되어 화면에 출력되고 종료되기까지, 컴파일러 툴체인과 리눅스 운영체제 커널 내부에서 발생하는 전체 실행 라이프사이클을 추적함.

---

## 1. 학습 목표 및 개요

- C 소스 코드(<code>hello.c</code>)가 전처리기, 컴파일러, 어셈블러, 링커를 거쳐 64비트 ELF 바이너리로 조립되는 과정을 규명함.
- 쉘 프롬프트에서 <code>./hello</code>를 입력했을 때 <code>execve()</code> 시스템 콜을 통해 Ring 0 커널 공간으로 제어권이 전이되는 메커니즘을 분석함.
- 리눅스 커널의 <code>load_elf_binary()</code> 함수가 가상 주소 공간(VMA)을 구성하고 PT_LOAD 세그먼트를 매핑하는 방식을 이해함.
- 동적 링커(<code>ld-linux.so</code>)와 C 런타임 시작 지점(<code>_start</code> ➔ <code>__libc_start_main</code>)을 거쳐 최종적으로 <code>main()</code> 함수가 호출되는 흐름을 학습함.

---

## 2. 인터랙티브 실행 파이프라인 다이어그램

아래 다이어그램을 통해 소스 코드 컴파일부터 커널 내부 진입 및 종료까지 5단계의 흐름을 단계별로 탐색 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/01-hello-lifecycle.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 4단계 빌드 파이프라인 심층 분석

C 소스 코드가 실행 파일로 변환되는 과정은 독립적인 4개의 소프트웨어 도구를 순차적으로 통과함:

```
[hello.c] ➔ [전처리기 cpp] ➔ [hello.i] ➔ [컴파일러 cc1] ➔ [hello.s]
          ➔ [어셈블러 as] ➔ [hello.o] ➔ [링커 ld]      ➔ [hello (ELF64)]
```

1. **전처리 단계 (Preprocessing - `cpp`)**:
   - `#include <stdio.h>`와 같은 표준 헤더 파일 내용을 소스 파일 내부로 복사하고, 매크로 정의 치환 및 주석 제거를 수행함.
2. **컴파일 단계 (Compilation - `cc1`)**:
   - 고수준 C 문법을 파싱하고 추상 구문 트리(AST)를 생성한 뒤, 타깃 아키텍처(x86_64 또는 ARM64)의 어셈블리 텍스트(<code>hello.s</code>)로 변환함.
3. **어셈블 단계 (Assembly - `as`)**:
   - 어셈블리 명령어를 기계어 바이트(Opcode)로 1:1 매핑하여 재배치 가능한 오브젝트 파일(<code>hello.o</code>, ELF Relocatable)을 생성함.
4. **링킹 단계 (Linking - `ld`)**:
   - C 런타임 기동 오브젝트(<code>crt1.o</code>, <code>crti.o</code>) 및 표준 라이브러리(<code>libc.so</code>)의 심볼 주소를 결합하여 최종 실행 가능한 ELF 바이너리를 완성함.

---

## 4. 커널 공간에서의 프로세스 로딩: `load_elf_binary()`

터미널에서 사용자가 바이너리를 실행하면 사용자 공간의 쉘과 리눅스 커널 사이에 다음과 같은 협업 파이프라인이 작동함:

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자 / 터미널
    participant Shell as 쉘 (Bash/Zsh)
    participant Kernel as 리눅스 커널 (Ring 0)
    participant Linker as 동적 링커 (ld-linux.so)
    participant Main as C 프로그램 (main)

    User->>Shell: ./hello 입력
    Shell->>Shell: fork() 호출 (자식 프로세스 복제)
    Shell->>Kernel: execve("./hello", argv, envp) 시스템 콜
    Kernel->>Kernel: do_execve() ➔ bprm_execve()
    Kernel->>Kernel: load_elf_binary() 호출
    Kernel->>Kernel: 기존 메모리 해제 & PT_LOAD 세그먼트 VMA 매핑
    Kernel->>Kernel: 인터프리터(PT_INTERP) 탐색 (/lib64/ld-linux-x86-64.so.2)
    Kernel->>Linker: Ring 3 복귀 및 동적 링커 엔트리 점프
    Linker->>Linker: 공유 라이브러리 로드 (libc.so) & PLT/GOT 릴로케이션
    Linker->>Main: _start ➔ __libc_start_main ➔ main() 진입
    Main->>Kernel: write(1, "Hello World\n", 12)
    Main->>Kernel: exit_group(0) 프로세스 종료
```

---

## 5. 실습 소스 코드 및 ELF 바이너리 분석

- **실습 소스 코드**: [`hello.c`](../../assets/labs/principles/01-hello-lifecycle/hello.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/01-hello-lifecycle/hello.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/01-hello-lifecycle/Makefile)

### 5.1 실습 코드 실행

```bash
cd labs/principles/01-hello-lifecycle
make run
```

```
=== [1] Running Hello World Binary ===
./hello
[+] Hello, System Security Principles!
[+] Process PID: 12458, PPID: 11020
[+] main() address: 0x55dc98a21149
[+] g_greeting (.rodata): 0x55dc98a22008
[+] g_run_counter (.data): 0x55dc98a24018 (value=1)
[+] argc: 1, argv[0]: ./hello
```

### 5.2 ELF 세그먼트 및 섹션 심층 분석

```bash
make inspect
```

- `readelf -h hello`: ELF 매직 넘버(`\x7fELF`) 및 아키텍처, 진입점(`Entry point: 0x1060`) 확인.
- `readelf -l hello`: 커널이 가상 메모리에 매핑하는 `PT_LOAD` 세그먼트와 읽기/쓰기/실행(`R E`, `RW `) 권한 확인.
- `readelf -S hello`: `.text`, `.rodata`, `.data`, `.bss` 섹션의 크기 및 메모리 오프셋 검증.

---

## 6. 요약 및 다음 강의

- `"Hello World"` 프로그램은 단순한 C 코드 한 줄이지만, 실행되기 위해 컴파일러 도구 체인, ELF 헤더 파싱, 커널의 `execve` 시스템 콜, 동적 링커의 심볼 재배치, C 런타임 초기화 단계를 유기적으로 거침.
- 다음 강의에서는 이렇게 메모리에 올라간 프로세스가 실제로 어떻게 64비트 가상 주소 공간을 분할하고 사용하는지 다루는 **[02. 리눅스 프로세스 구조와 가상 메모리 공간](02-virtual-memory-layout.md)**을 학습함.
