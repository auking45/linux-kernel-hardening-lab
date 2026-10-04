# 07. 심볼 테이블과 링킹 메커니즘 (Symbols & Relocation)

독립적으로 컴파일된 여러 오브젝트 파일(`.o`)들이 하나의 실행 바이너리로 결합될 때, 변수와 함수 이름을 실제 메모리 주소로 바인딩하는 **심볼 해석(Symbol Resolution)**과 기계어 명령어 내 임시 주소를 패치하는 **릴로케이션(Relocation)** 메커니즘을 분석함.

---

## 1. 학습 목표 및 개요

- ELF 심볼 테이블(`Elf64_Sym`)의 바이트 구조와 심볼 바인딩(Local, Global, Weak)의 차이를 이해함.
- 링커가 복수의 심볼 정의를 마주했을 때 적용하는 **Strong vs Weak 심볼 해석 3대 규칙**을 규명함.
- C와 C++ 언어의 심볼 이름 생성 방식 차이(Name Mangling)를 비교함.
- 미완성 기계어 명령어의 피연산자를 최종 메모리 오프셋으로 수정하는 **릴로케이션 공식(`S + A - P`)**을 바이트 단위로 계산함.

---

## 2. 인터랙티브 심볼 해석 & 릴로케이션 다이어그램

아래 다이어그램에서 4단계(미해결 심볼 수집 ➔ Strong/Weak 해석 ➔ 섹션 병합 ➔ 릴로케이션 패치)를 거치며 심볼 테이블과 기계어 바이트가 어떻게 완성되는지 확인 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/07-symbols-linking.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 심볼의 본질과 심볼 테이블 구조 (`Elf64_Sym`)

프로그래머가 작성한 함수명과 변수명은 컴파일러에 의해 심볼(Symbol)로 등록되며, 링커는 이를 메모리 주소로 치환함:

```c
typedef struct {
    Elf64_Word    st_name;  /* .strtab 문자열 테이블 내 이름 오프셋 */
    unsigned char st_info;  /* 심볼 타입(STT_FUNC, STT_OBJECT) 및 바인딩(STB_LOCAL, STB_GLOBAL, STB_WEAK) */
    unsigned char st_other; /* 가시성(STV_DEFAULT, STV_HIDDEN) */
    Elf64_Section st_shndx; /* 정의된 섹션 인덱스 (미해결 시 SHN_UNDEF) */
    Elf64_Addr    st_value; /* 섹션 내 오프셋 또는 확정된 가상 주소 */
    Elf64_Xword   st_size;  /* 심볼 객체의 크기(바이트) */
} Elf64_Sym;
```

---

## 4. Strong vs Weak 심볼 해석 3대 규칙

C 언어에서 함수와 초기화된 전역 변수는 **Strong 심볼**로 취급되며, 미초기화 전역 변수나 `__attribute__((weak))` 선언 함수는 **Weak 심볼**로 분류됨:

1. **규칙 1 (동일 Strong 심볼 충돌 금지)**:
   - 복수의 오브젝트 파일에서 동일한 이름의 Strong 심볼이 정의되어 있으면 링커 에러(`multiple definition of ...`)가 발생함.
2. **규칙 2 (Strong 심볼 우선 채택)**:
   - 하나의 Strong 심볼과 여러 개의 Weak 심볼이 동일 이름으로 존재할 경우, 링커는 에러 없이 **Strong 심볼을 최종 선택**함 (Weak 심볼 오버라이딩).
3. **규칙 3 (Weak 심볼 간 임의 선택)**:
   - Weak 심볼만 복수 개 존재할 경우, 링커는 경고 없이 그중 임의의 하나를 선택하여 바인딩함.

> [!TIP]
> **시스템 보안 및 라이브러리 인터셉트**:
> 표준 C 라이브러리(glibc)의 많은 함수(예: `malloc`, `free`, 시스템 콜 래퍼)는 기본적으로 Weak 심볼로 제공됨. 이를 통해 성능 프로파일러(tcmalloc, jemalloc)나 보안 감사 도구가 애플리케이션 레벨에서 라이브러리 루틴을 손쉽게 가로채 오버라이드할 수 있음.

---

## 5. 릴로케이션(Relocation) 연산 메커니즘

컴파일러는 `main.o`를 빌드할 때 외부 함수 `calculate_add()`의 주소를 알지 못하므로 `call` 명령어 뒤에 임시 바이트(`e8 00 00 00 00`)를 넣고 릴로케이션 테이블(`.rela.text`)에 기록함:

### 5.1 x86_64 대표 릴로케이션 공식

- **`R_X86_64_PC32` (32비트 PC-상대 오프셋)**:
  $$\text{Offset} = S + A - P$$
  - $S$ (Symbol): 참조할 타깃 함수의 최종 가상 주소.
  - $A$ (Addend): 릴로케이션 엔트리에 기록된 보정 상수 (통상 `-4`).
  - $P$ (Place): 릴로케이션 패치가 일어나는 현재 기계어의 가상 주소.
- **`R_X86_64_64` (64비트 절대 주소)**:
  $$\text{Address} = S + A$$

---

## 6. 실습 소스 코드 및 Weak 심볼 오버라이딩 검증

- **실습 소스 코드**: [`main.c`](../../assets/labs/principles/07-symbols-linking/main.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/07-symbols-linking/main.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/07-symbols-linking/Makefile)

### 6.1 Weak 심볼 기본 빌드 실행

```bash
cd labs/principles/07-symbols-linking
make run
```

```
=== [1] Running Default Build (Weak Symbol in effect) ===
./sym_demo_default
============================================================
 Symbol Resolution & Relocation Demonstration
============================================================
[+] calculate_add(10, 20) = 30
[+] g_operation_count address: 0x404024 (val=1)
[+] Calling custom_hook() at 0x4011e0:
    [calc.c] Default WEAK hook executed (no override provided).
============================================================
```

### 6.2 Strong 심볼을 통한 오버라이딩 실행

```bash
make run-override
```

```
=== [2] Running Override Build (Strong Symbol overrides Weak) ===
./sym_demo_override
============================================================
 Symbol Resolution & Relocation Demonstration
============================================================
[+] calculate_add(10, 20) = 30
[+] g_operation_count address: 0x404024 (val=1)
[+] Calling custom_hook() at 0x4011e0:
    [weak_override.c] ★ STRONG hook successfully overrode the weak symbol!
============================================================
```

- `weak_override.c`가 링크에 포함되면 링커 에러 없이 Strong 버전의 `custom_hook()`으로 대체되는 과정을 실증함.

---

## 7. 요약 및 다음 강의

- 링커는 심볼 테이블을 통해 미해결 참조를 해결하고, 릴로케이션 연산식을 통해 기계어 명령어의 피연산자를 최종 메모리 오프셋으로 패치함.
- 다음 강의에서는 이 모든 오브젝트 모듈과 C 런타임을 하나의 거대한 단일 실행 파일로 영구 결합하는 **[08. 정적 링킹과 바이너리 로딩](08-static-linking-and-loading.md)**을 학습함.
