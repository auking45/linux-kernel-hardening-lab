# 06. 컴파일 과정과 ELF 파일 구조 심층 분석 (Compilation & ELF File Format)

소스 코드가 컴파일러 툴체인을 거쳐 기계어로 변환되는 저수준 파이프라인과, 리눅스 실행 파일 표준 규격인 **ELF (Executable and Linkable Format)의 이중 뷰(Dual View: Linking View vs Execution View)** 아키텍처를 심층 분석함.

---

## 1. 학습 목표 및 개요

- C 소스 코드가 어휘 분석, 구문 분석, 중간 표현(IR) 생성, 기계어 어셈블리를 거쳐 ELF 파일로 패키징되는 전 과정을 이해함.
- ELF 포맷이 제공하는 **링킹 뷰(섹션 중심, Section Header)**와 **실행 뷰(세그먼트 중심, Program Header)**의 이중적 설계 목적을 규명함.
- ELF 헤더(`Elf64_Ehdr`)의 64바이트 필드 구조와 매직 넘버(`\x7fELF`)의 커널 검증 원리를 학습함.
- `PT_LOAD`, `PT_INTERP`, `PT_GNU_STACK` 등 커널 로더가 프로세스 가상 메모리 VMA를 생성할 때 참조하는 핵심 세그먼트 메타데이터를 파싱함.

---

## 2. 인터랙티브 ELF 파일 구조 및 이중 뷰 다이어그램

아래 다이어그램에서 ELF 헤더부터 각 세그먼트와 섹션의 매핑 관계, 그리고 W^X 메모리 권한 플래그를 인터랙티브하게 확인 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/06-elf-structure.html" style="width: 100%; min-height: 680px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const h = this.contentWindow.document.documentElement.scrollHeight; if(h) this.style.height = (h + 30) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 컴파일러 내부의 단계별 코드 변환 파이프라인

고수준 C 코드가 CPU 기계어로 강등되는 과정은 컴파일러 프론트엔드와 백엔드의 다단계 변환 파이프라인으로 구성됨:

```mermaid
flowchart LR
    A["C 소스 코드"] --> B["어휘 분석 (Lexer)"]
    B --> C["구문 분석 (Parser: AST)"]
    C --> D["중간 표현 (LLVM IR / GIMPLE)"]
    D --> E["최적화 (Optimization Passes)"]
    E --> F["어셈블리 생성 (ASM: .s)"]
    F --> G["어셈블러 (as ➔ .o)"]
    G --> H["링커 (ld ➔ ELF64)"]

    style A fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#fff
    style D fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#fff
    style H fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#fff
```

1. **어휘 및 구문 분석 (Lexical & Syntax Analysis)**:
   - 소스 코드를 토큰(Token) 스트림으로 쪼갠 뒤 문법 규칙에 따라 추상 구문 트리(AST)를 구성함.
2. **중간 표현 생성 및 최적화 (IR & Optimization)**:
   - 아키텍처 중립적인 중간 언어(LLVM IR)로 변환한 후 데드 코드 제거, 루프 언롤링, 인라인화 최적화를 수행함.
3. **코드 생성 및 어셈블 (Code Generation & Assembler)**:
   - x86_64 또는 ARM64 레지스터 할당 및 명령어 스케줄링을 거쳐 어셈블리 텍스트를 생성하고, 어셈블러가 이를 재배치 가능한 기계어 오브젝트(`.o`)로 출력함.

---

## 4. ELF 이중 뷰(Dual View) 아키텍처 비교

ELF 규격은 소프트웨어 라이프사이클의 두 주체인 **링커(Linker)**와 **커널 로더(Loader)**를 동시에 만족시키기 위해 2가지 관점의 테이블을 병행 제공함:

```
[ Linking View: 섹션 중심 ]                     [ Execution View: 세그먼트 중심 ]
  (링커 ld 및 디버거가 사용)                      (커널 load_elf_binary가 사용)
┌─────────────────────────┐                   ┌─────────────────────────┐
│       ELF Header        │                   │       ELF Header        │
├─────────────────────────┤                   ├─────────────────────────┤
│  Program Header Table   │ (선택 사항)        │  Program Header Table   │ (필수!)
├─────────────────────────┤                   ├─────────────────────────┤
│  .text / .init / .plt   │ ──(번들링)───────> │  PT_LOAD 1 (RX)         │ (코드 세그먼트)
├─────────────────────────┤                   ├─────────────────────────┤
│  .rodata / .eh_frame    │ ──(번들링)───────> │  PT_LOAD 2 (R--)        │ (읽기 전용 세그먼트)
├─────────────────────────┤                   ├─────────────────────────┤
│  .data / .bss / .got    │ ──(번들링)───────> │  PT_LOAD 3 (RW-)        │ (데이터 세그먼트)
├─────────────────────────┤                   ├─────────────────────────┤
│  Section Header Table   │ (필수!)           │  Section Header Table   │ (선택/strip 가능)
└─────────────────────────┘                   └─────────────────────────┘
```

### 4.1 핵심 ELF 헤더 구조체 필드 (`Elf64_Ehdr`)

| 필드명 | 데이터 타입 | 설명 및 보안/로딩 역할 |
| :--- | :--- | :--- |
| `e_ident[EI_MAG0..3]` | `unsigned char[4]` | ELF 매직 넘버 (`0x7f, 'E', 'L', 'F'`). 커널의 첫 유효성 검증 대상 |
| `e_type` | `Elf64_Half` | `ET_EXEC`(고정 주소 실행 파일), `ET_DYN`(PIE / 공유 라이브러리) |
| `e_machine` | `Elf64_Half` | 타깃 하드웨어 아키텍처 (`EM_X86_64 = 62`, `EM_AARCH64 = 183`) |
| `e_entry` | `Elf64_Addr` | 프로세스 실행 진입점 가상 주소 (`_start` 위치) |
| `e_phoff` / `e_phnum` | `Elf64_Off / Half` | Program Header Table의 파일 내 오프셋 및 엔트리 개수 |
| `e_shoff` / `e_shnum` | `Elf64_Off / Half` | Section Header Table의 파일 내 오프셋 및 엔트리 개수 |

---

## 5. 실습 소스 코드 및 ELF 직접 파싱

- **실습 소스 코드**: [`elf_inspector.c`](../../assets/labs/principles/06-elf-structure/elf_inspector.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/06-elf-structure/elf_inspector.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/06-elf-structure/Makefile)

### 5.1 C 언어 기반 ELF 파서 빌드 및 실행

```bash
cd labs/principles/06-elf-structure
make inspect-self
```

```
============================================================
 64-bit ELF Header Inspection: elf_inspector
============================================================
[1] Magic Bytes      : 7f 45 4c 46 (ASCII: \x7fELF)
[2] Architecture     : ELF64 (64-bit)
[3] Data Encoding    : 2's complement, Little Endian
[4] Entry Point      : 0x401130
[5] Program Headers  : Offset 0x40 (13 entries, size 56 bytes)
[6] Section Headers  : Offset 0x3890 (30 entries, size 64 bytes)
============================================================

=== [Execution View] Program Headers (Segments) ===
Type               Offset     VirtAddr           MemSize    Flags 
-----------------------------------------------------------------
PT_PHDR            0x40       0x400040           0x2d8      R--
PT_INTERP          0x318      0x400318           0x1c       R--
PT_LOAD            0x0        0x400000           0x780      R--
PT_LOAD            0x1000     0x401000           0x691      R-E
PT_LOAD            0x2000     0x402000           0x6cc      R--
PT_LOAD            0x2de8     0x403de8           0x2a8      RW-
PT_GNU_STACK       0x0        0x0                0x0        RW-
PT_GNU_RELRO       0x2de8     0x403de8           0x218      R--
```

- `elf_inspector` 실행 결과, 코드 영역(`PT_LOAD R-E`)과 데이터 영역(`PT_LOAD RW-`), 스택 영역(`PT_GNU_STACK RW-` ➔ NX 적용)의 권한 분리를 확인할 수 있음.

---

## 6. 요약 및 다음 강의

- ELF 파일은 링커가 모듈을 조립하기 위한 섹션 테이블(Linking View)과 커널이 가상 메모리에 매핑하기 위한 세그먼트 테이블(Execution View)을 분리 제공함.
- 다음 강의에서는 여러 오브젝트 파일 속의 함수와 변수 이름을 실제 메모리 주소로 연결하는 **[07. 심볼 테이블과 링킹 메커니즘](07-symbols-and-linking.md)**을 학습함.
