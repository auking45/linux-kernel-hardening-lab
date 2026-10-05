# 02. 리눅스 프로세스 구조와 가상 메모리 공간 (Virtual Address Space)

운영체제에서 실행되는 모든 리눅스 프로세스는 하드웨어 물리 메모리를 직접 보지 않고, 커널과 MMU(Memory Management Unit)가 제공하는 독립적인 **64비트 가상 주소 공간(Virtual Address Space)**에서 독점적으로 동작함. 모바일 및 디바이스 시스템 보안의 핵심인 **AArch64(ARM64)** 아키텍처를 기본(Default)으로 분석하며, **x86_64**와의 주소 변환 아키텍처 차이를 심층 비교함.

---

## 1. 학습 목표 및 개요

- 64비트 AArch64 및 x86_64 아키텍처의 가상 메모리 분할 구조(유저 공간 vs 커널 공간)를 이해함.
- AArch64의 이중 변환 테이블 베이스 레지스터(`TTBR0_EL1` vs `TTBR1_EL1`) 분리 구조와 x86_64 `CR3` 정규 주소 홀(Canonical Hole) 구조를 비교 대조함.
- 프로세스를 구성하는 7대 핵심 메모리 세그먼트(`.text`, `.rodata`, `.data`, `.bss`, Heap, mmap, Stack)의 역할과 메모리 권한을 규명함.
- 현대 운영체제 보안의 기본 축인 **W^X (Write XOR Execute)** 원칙의 하드웨어 구현 방식을 분석함.
- `/proc/self/maps` 가상 파일을 통해 실제 실행 중인 프로세스의 VMA(Virtual Memory Area) 매핑을 검증함.

---

## 2. 인터랙티브 가상 메모리 맵 인스펙터

아래 메모리 타워를 클릭하여 최상위 커널 공간부터 최하위 널 트랩 구역까지 각 세그먼트의 상세 설명과 보안 함의를 확인 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/02-virtual-memory.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 64비트 가상 메모리 주소 체계 해부: AArch64 vs x86_64

현대 64비트 프로세서는 64비트 주소 전체($2^{64} \approx 16 \text{ EB}$)를 사용하지 않고, 48비트 가상 주소 체계($2^{48} = 256 \text{ TB}$)를 주로 사용함:

```
[0xFFFFFFFFFFFFFFFF] ───────────┐
                                │ 커널 공간 (Upper Half)
[0xFFFF000000000000] ───────────┘ (AArch64: TTBR1_EL1 / x86_64: CR3 최상위)
                                
  ( Non-Canonical / Unmapped )   주소 미할당 공간 (접근 시 하드웨어 트랩/예외 발생)
                                
[0x0000FFFFFFFFFFFF] ───────────┐ (AArch64: TTBR0_EL1)
                                │ 유저 공간 (Lower Half)
[0x0000000000000000] ───────────┘
```

### 3.1 AArch64의 하드웨어 주소 분할 혁신 (`TTBR0_EL1` vs `TTBR1_EL1`)

ARM64 아키텍처는 유저 공간과 커널 공간의 분리를 하드웨어 레지스터 수준에서 물리적으로 양분함:

1. **`TTBR0_EL1` (Translation Table Base Register 0)**:
   - 유저 공간(`0x0000_0000_0000_0000 ~ 0x0000_FFFF_FFFF_FFFF`) 전용 변환 테이블의 베이스 주소를 보유함.
   - 프로세스 문맥 교환(Context Switch) 발생 시 커널은 `TTBR0_EL1`만 새 프로세스의 페이지 테이블로 교체함.
2. **`TTBR1_EL1` (Translation Table Base Register 1)**:
   - 커널 공간(`0xFFFF_0000_0000_0000 ~ 0xFFFF_FFFF_FFFF_FFFF`) 전용 변환 테이블의 베이스 주소를 영구 보유함.
   - 문맥 교환 시 커널 매핑을 건드릴 필요가 없어 TLB 플러시 오버헤드가 극적으로 감소함.
3. **`TCR_EL1` (Translation Control Register)**:
   - `T0SZ`와 `T1SZ` 필드를 통해 유저/커널 각 영역의 주소 비트 크기(39비트, 48비트, 52비트)를 독립적으로 제어함.

### 3.2 x86_64의 정규 주소(Canonical Address) 규칙

x86_64는 단일 제어 레지스터(`CR3`)가 4단계(PML4) 또는 5단계(PML5) 페이지 디렉터리를 가리킴:

- 48비트 주소 체계에서 최상위 16개 비트(비트 48~63)는 47번 비트와 동일하게 부호 확장(Sign Extension)되어야 함.
- 47번 비트가 `0`이면 `0x00007FFFFFFFFFFF` 이하(유저 공간), `1`이면 `0xFFFF800000000000` 이상(커널 공간)만 유효함.
- 그 사이의 거대한 미할당 구역(약 16,777,216 TB)에 접근하면 CPU 하드웨어가 일반 보호 예외(`#GP Fault`)를 발생시킴.

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
| **Stack** | `rw-p` | 함수 스택 프레임, 지역 변수, 반환 주소(LR / RET) | **아래로 성장 (▼)** |

> [!IMPORTANT]
> **W^X (Write XOR Execute) 보안 원칙**:
> 현대 운영체제는 동일한 메모리 페이지에 쓰기(Write) 권한과 실행(Execute) 권한을 동시에 부여하지 않음(`W ^ X`). 데이터가 기록되는 스택이나 힙은 실행이 금지(No-Execute / NX, ARM: XN / Execute-Never)되며, 실행되는 코드 영역은 변조(Write)가 원천 차단됨.

---

## 5. 실습 소스 코드 및 가상 메모리 맵 검증

- **실습 소스 코드**: [`address_space_demo.c`](../../assets/labs/principles/02-address-space/address_space_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/02-address-space/address_space_demo.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/02-address-space/Makefile)

### 5.1 세그먼트 주소 배치 출력

=== "AArch64 (기본 타깃)"
    ```bash
    cd labs/principles/02-address-space
    make run
    ```

    ```
    === Running address_space_demo on aarch64 ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./address_space_demo
    ============================================================
     64-bit Process Virtual Address Space Inspection (PID: 34)
    ============================================================
    [1] Code Segment (.text)       : 0x74fe76c80c30 (main)
                                   : 0x74fe76c80c28 (dummy_function)
    [2] Read-Only Data (.rodata)   : 0x74fe76c80e70 ("System Security Principles 2026")
    [3] Initialized Data (.data)   : 0x74fe76ca0010 (0x1337)
    [4] Uninitialized Data (.bss)  : 0x74fe76ca0018 (0x0)
    [5] Heap Segment (malloc)      : 0x400000a3e2a0 (size=256)
    [6] Memory Mapped Region (mmap): 0x400000b3e000 (page-aligned)
    [7] Shared Library (libc)      : 0x4000008c0410 (printf)
    [8] Stack Segment (RSP area)   : 0x4000007fedb4 (&local_stack_var)
                                   : 0x4000007fedac (&argc)
    [9] Kernel Space Boundary      : 0xffff800000000000 (x86_64) / 0xffff000000000000 (ARM64)
    ```

=== "x86_64 (비교 타깃)"
    ```bash
    cd labs/principles/02-address-space
    make ARCH=x86_64 run
    ```

    ```
    === Running address_space_demo on x86_64 ===
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
- AArch64는 `TTBR0_EL1`과 `TTBR1_EL1`을 통해 유저와 커널 페이지 테이블을 하드웨어 수준에서 물리적으로 완벽히 격리함.
- 다음 강의에서는 이 중에서도 함수가 호출될 때마다 동적으로 생성되고 소멸하며 보안 취약점의 핵심 무대가 되는 **[03. 스택 프레임 구조와 함수 호출 규약(ABI)](03-stack-frame-and-abi.md)**을 집중 분석함.
