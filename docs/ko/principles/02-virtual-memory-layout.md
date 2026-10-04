# 02. 리눅스 프로세스 구조와 가상 메모리 공간 (Virtual Address Space)

운영체제에서 실행되는 모든 리눅스 프로세스는 하드웨어 물리 메모리를 직접 보지 않고, 커널과 MMU(Memory Management Unit)가 제공하는 독립적인 **64비트 가상 주소 공간(Virtual Address Space)**에서 독점적으로 동작함.

---

## 1. 학습 목표 및 개요

- 64비트 x86_64 및 ARM64 아키텍처의 가상 메모리 분할 구조(128TB 유저 영역 vs 128TB 커널 영역)를 이해함.
- 비정규 주소 홀(Non-Canonical Address Hole)의 존재 이유와 CPU 수준의 하드웨어 트랩 원리를 분석함.
- 프로세스를 구성하는 7대 핵심 메모리 세그먼트(`.text`, `.rodata`, `.data`, `.bss`, Heap, mmap, Stack)의 역할과 메모리 권한을 규명함.
- `/proc/self/maps` 가상 파일을 통해 실제 실행 중인 프로세스의 VMA(Virtual Memory Area) 매핑을 검증함.

---

## 2. 인터랙티브 가상 메모리 맵 인스펙터

아래 메모리 타워를 클릭하여 최상위 커널 공간부터 최하위 널 트랩 구역까지 각 세그먼트의 상세 설명과 보안 함의를 확인 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/02-virtual-memory.html" style="width: 100%; min-height: 680px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const h = this.contentWindow.document.documentElement.scrollHeight; if(h) this.style.height = (h + 30) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 64비트 가상 메모리 주소 체계 해부

현대 64비트 프로세서는 64비트 주소 전체($2^{64} \approx 16 \text{ EB}$)를 사용하지 않고, 48비트 가상 주소 체계($2^{48} = 256 \text{ TB}$)를 사용함:

```
[0xFFFFFFFFFFFFFFFF] ───────────┐
                                │ 커널 공간 (128 TB)
[0xFFFF800000000000] ───────────┘
                                
  ( Non-Canonical Hole )         약 16,777,216 TB의 주소 미할당 공간
                                   (접근 시 CPU 하드웨어 #GP 예외 발생)
                                
[0x00007FFFFFFFFFFF] ───────────┐
                                │ 유저 공간 (128 TB)
[0x0000000000000000] ───────────┘
```

1. **정규 주소(Canonical Address) 규칙**:
   - 48비트 주소 체계에서 47번 비트가 부호 비트 역할을 담당함.
   - 48번부터 63번까지의 16개 상위 비트는 47번 비트의 값과 완벽히 동일하게 부호 확장(Sign Extension)되어야 함.
   - 따라서 합법적인 주소는 최상위 `0xFFFF...`로 시작하거나 최하위 `0x0000...`로 시작하는 두 영역으로만 양분됨.
2. **유저 공간과 커널 공간의 하드웨어 격리**:
   - 유저 공간(`0x0000000000000000 ~ 0x00007FFFFFFFFFFF`)은 각 프로세스마다 고유한 독립 페이지 테이블을 보유함.
   - 커널 공간(`0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF`)은 CPU의 Supervisor 권한(Ring 0 / EL1)에서만 접근 가능하며 비인가 유저 접근 시 Page Fault(`#PF`)를 유발함.

---

## 4. 7대 메모리 세그먼트와 W^X 보안 원칙

리눅스 커널은 메모리 안정성과 보안을 보장하기 위해 각 영역별로 페이지 권한 비트(`r-xp`, `rw-p`, `r--p`)를 엄격히 분리함:

| 세그먼트 | 메모리 권한 | 주요 저장 내용 및 특징 | 성장 방향 |
| :--- | :---: | :--- | :---: |
| **Code / Text** | `r-xp` | 컴파일된 CPU 기계어 명령어, 함수 본체 | 고정 |
| **ROData** | `r--p` | 상수 문자열 리터럴, const 전역 변수 | 고정 |
| **Data** | `rw-p` | 초기화된 전역 및 정적(static) 변수 | 고정 |
| **BSS** | `rw-p` | 초기화되지 않은 전역 변수 (Demand Zeroing) | 고정 |
| **Heap** | `rw-p` | `malloc()` / `new` 동적 할당 풀 (`brk`) | **위로 성장 (▲)** |
| **mmap Region** | `r-xp` / `rw-p` | 공유 라이브러리(`libc.so`), 익명 메모리 매핑 | 동적 배치 |
| **Stack** | `rw-p` | 함수 스택 프레임, 지역 변수, 반환 주소(RET) | **아래로 성장 (▼)** |

> [!IMPORTANT]
> **W^X (Write XOR Execute) 보안 원칙**:
> 현대 운영체제는 동일한 메모리 페이지에 쓰기(Write) 권한과 실행(Execute) 권한을 동시에 부여하지 않음(`W ^ X`). 데이터가 쓰여지는 스택이나 힙은 실행이 금지(No-Execute / NX)되며, 실행되는 코드 영역은 변조(Write)가 원천 금지됨.

---

## 5. 실습 소스 코드 및 가상 메모리 맵 검증

- **실습 소스 코드**: [`address_space_demo.c`](../../assets/labs/principles/02-address-space/address_space_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/02-address-space/address_space_demo.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/02-address-space/Makefile)

### 5.1 세그먼트 주소 배치 출력

```bash
cd labs/principles/02-address-space
make run
```

```
============================================================
 64-bit Process Virtual Address Space Inspection (PID: 12580)
============================================================
[1] Code Segment (.text)       : 0x559e2b101149 (main)
                               : 0x559e2b101230 (dummy_function)
[2] Read-Only Data (.rodata)   : 0x559e2b102008 ("System Security Principles 2026")
[3] Initialized Data (.data)   : 0x559e2b104018 (0x1337)
[4] Uninitialized Data (.bss)  : 0x559e2b104020 (0x0)
[5] Heap Segment (malloc)      : 0x559e2cb032a0 (size=256)
[6] Memory Mapped Region (mmap): 0x7fa28c500000 (page-aligned)
[7] Shared Library (libc)      : 0x7fa28c312e40 (printf)
[8] Stack Segment (RSP area)   : 0x7ffd582a8934 (&local_stack_var)
                               : 0x7ffd582a894c (&argc)
[9] Kernel Space Boundary      : 0xffff800000000000 (x86_64) / 0xffff000000000000 (ARM64)
```

### 5.2 실제 `/proc/self/maps` 확인

```bash
make run-maps
```

- 실제 바이너리의 코드 영역이 `r-xp`로 매핑되고, 데이터가 `rw-p`, 스택 영역이 `[stack] rw-p`로 커널에 의해 관리되고 있음을 확인 가능함.

---

## 6. 요약 및 다음 강의

- 리눅스 프로세스는 텍스트, 데이터, 힙, mmap, 스택으로 구성된 정교한 가상 메모리 공간에서 실행됨.
- 다음 강의에서는 이 중에서도 함수가 호출될 때마다 동적으로 생성되고 소멸하며 보안 취약점의 핵심 무대가 되는 **[03. 스택 프레임 구조와 함수 호출 규약(ABI)](03-stack-frame-and-abi.md)**을 집중 분석함.
