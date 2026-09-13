# [Skill Specification] Linux Kernel Hardening Lab Documentation & Engineering Standard

본 문서는 **Linux Kernel Hardening Lab**의 모든 기술 문서(한국어/영어), Archify 및 Mermaid 아키텍처 다이어그램, Kconfig 설정 프래그먼트, 실습 랩 코드 및 QEMU 검증 스크립트를 작성할 때 준수해야 하는 **엔지니어링 표준 가이드라인(Authoring Standard)**을 정의함.

---

## 1. Tone & Style Guidelines (문체 및 어조 표준)

### 🇰🇷 한국어 기술 문서 규격 (명사 종결형 필수 준수)

1. **명사 종결형 원칙**:
   - 존댓말("~합니다 / ~했습니다 / ~됩니다") 사용을 **절대 금지함**.
   - 구어체 서술형 평서체("~다 / ~한다 / ~이다") 또한 지양함.
   - **간결한 개조식 명사 종결형("~함", "~임", "~제공", "~수행", "~차단", "~비교", 명사/명사구)**으로 문장을 완결함.
   - **모범 예시 (Good)**:
     - `스택 카나리(Stack Canary)를 통한 함수 프롤로그/에필로그 스택 무결성 검증.`
     - `커널 메모리 공간 내 함수 주소 무작위 배치를 수행하여 ROP 가젯 체이닝 차단.`
     - `ARM64 환경에서 PAC 레지스터 인증 실패 시 유효하지 않은 주소로 예외 발생 유도함.`
   - **금지 예시 (Bad)**:
     - `스택 카나리는 버퍼 오버플로우를 감지합니다.` (X)
     - `함수 주소를 무작위로 배치하여 공격을 차단한다.` (X)
2. **기술적 정밀성 및 용어 표기 원칙**:
   - 리눅스 커널 공식 용어 및 하드웨어 아키텍처 명칭을 정확히 표기함.
   - 필요 시 영문 원어 및 약어를 병기함 (예: 제어 흐름 무결성(CFI, Control Flow Integrity), 간접 분기 추적(IBT, Indirect Branch Tracking)).
   - Kconfig 심볼은 백틱과 함께 대문자로 표기함 (예: `CONFIG_STACKPROTECTOR_STRONG`).

### 🇺🇸 영어 기술 문서 규격

1. **Concise & Active Engineering Voice**:
   - Write in direct, technical, active voice. Avoid filler phrases and conversational transitions.
2. **Standard Linux Kernel Nomenclature**:
   - Adhere to official Linux kernel documentation and kernel hardening community naming standards.

---

## 2. Visual-First & Diagram Guidelines (시각화 표준)

모든 아티클은 텍스트 중심 서술 이전에 직관적인 시각 자료를 필수로 배치함.

### 1. Archify 인터랙티브 다이어그램 규격 (`tt-a1i/archify`)

- **용도:** 시스템 전반의 아키텍처 맵, 커널 메모리 레이아웃 구조, 하위 보안 서브시스템 간의 연결 관계 시각화.
- **배치 방식:**
  - Archify를 통해 생성된 인터랙티브 HTML 파일은 `docs/assets/diagrams/<feature>/` 디렉터리에 저장함.
  - 마크다운 본문에서는 iframe 태그를 사용하여 반응형으로 임베드함:
    ```html
    <div class="archify-container">
      <iframe
        src="../../assets/diagrams/stack-protector/architecture.html"
        width="100%"
        height="450px"
        frameborder="0"
      ></iframe>
    </div>
    ```
  - 오프라인 또는 이미지 뷰어를 위해 동일한 구조의 SVG/PNG 스냅샷을 함께 보관함.

### 2. Mermaid 다이어그램 규격

- **용도:** 프로세스 흐름도, 시퀀스 다이어그램, 공격 시나리오(Exploit) vs 방어 메커니즘 비교.
- **테마 호환성:**
  - 다크 모드와 라이트 모드 모두에서 명확히 식별 가능하도록 하드코딩된 색상 인라인 스타일을 배제함.
  - Mermaid 코드 블록(` ```mermaid `)을 표준 규격으로 작성함.

---

## 3. Article Structure & Standards (아티클 표준 구성)

각 하드닝 피처 문서는 다음 6단계 구조를 엄격히 준수하여 일관된 학습 경험을 제공함:

````markdown
# [피처 이름] ([Kconfig 심볼 / 메커니즘 명칭])

## 1. 개요 및 위협 모델 (Overview & Threat Model)

- 방어 대상 취약점 유형 (예: Stack-based Buffer Overflow, Return-Oriented Programming, Meltdown).
- 공격 벡터 및 위험도 분석.

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

- Archify 아키텍처 맵 또는 Mermaid 시퀀스 다이어그램 배치.
- 컴파일러 및 하드웨어 CPU 수준에서의 동작 원리 분석.
- **실전 ROP 체인 및 공격 메커니즘 심층 해설 (Dual-Arch ROP Mechanics)**:
  - 스택 프레임 레이아웃 및 가젯(Gadget) 도미노 연쇄 원리.
  - **x86_64 vs ARM64(AArch64) ROP/JOP 구조 비교**:
    - x86_64: `ret` (스택 기반 RIP 팝) + 레지스터 인자(`rdi`) + `iretq/KPTI` 트램펄린 복귀.
    - ARM64: `ret` (`x30/lr` 기반 분기) + 레지스터 인자(`x0`) + `eret/ret_to_user` 복귀.
  - 커널 자격증명 승격(`commit_creds(&init_cred)`) 및 유저스페이스 안전 복귀 절차.
  - 해당 하드닝 기능이 ROP 체인의 어느 지점을 절단(Intercept)하여 무력화하는지 명시.

## 3. Kconfig 설정 및 부팅 파라미터 (Configuration)

- 관련 커널 설정 옵션 (`CONFIG_*`) 및 디펜던시 명시.
- 런타임 부팅 파라미터 및 sysctl 제어 항목 표 정리.

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

- 단순 크래시 관찰(LKDTM)과 **실전 권한 상승 ROP Exploit PoC(일반 유저 -> Root 셸)**를 함께 제공:
  1. **LKDTM 기반 방어 검증**: 커널 내장 모듈의 빠른 차단 여부 확인.
  2. **실전 ROP Exploit PoC (Dual-Arch: x86_64 & ARM64)**:
     - 비권한 일반 계정(`lab`, UID 1000)에서 취약 인터페이스를 향해 ROP 페이로드 주입.
     - **Base 커널 (보호 미적용)**: ROP 체인이 실행되어 `uid=0` (Root) 셸 탈취 성공 또는 통제 불능 크래시(GPF/Fault).
     - **Hardened 커널 (보호 적용)**: ROP 첫 가젯 실행 직전 해당 하드닝 기능이 즉시 탐지하여 패닉/안전 차단.
- 듀얼 아키텍처(x86_64 / arm64) 및 Base vs Hardened 탭 제공:

=== "x86_64: Hardened Kernel (적용: ROP 차단 - 권장)"
    ```bash
    ./scripts/run_lab.sh --arch x86_64 --feature <name> --test test_<name>
    # 결과 로그: ROP 진입 전 커널 패닉 / 안전 차단
    ```

=== "x86_64: Base Kernel (미적용: Exploit 성공)"
    ```bash
    ./scripts/run_lab.sh --arch x86_64 --feature <name>-disabled --test test_<name>
    # 결과 로그: ROP 체인 실행 -> UID=0 (Root Shell 획득) 또는 제어 흐름 탈취 크래시
    ```

=== "ARM64: Hardened Kernel (적용: ROP 차단)"
    ```bash
    ./scripts/run_lab.sh --arch arm64 --feature <name> --test test_<name>
    # 결과 로그: ARM64 ROP 진입 전 커널 패닉 / 안전 차단
    ```

=== "ARM64: Base Kernel (미적용: Exploit 성공)"
    ```bash
    ./scripts/run_lab.sh --arch arm64 --feature <name>-disabled --test test_<name>
    # 결과 로그: ARM64 ROP/JOP 체인 실행 -> UID=0 획득 또는 분기 실패 예외
    ```

## 5. 성능 및 호환성 분석 (Performance & Compatibility)

- CPU 연산 오버헤드, 바이너리 크기 증가율, 런타임 메모리 사용량 비교.
- 운영 환경(서버, 임베디드, 안드로이드 등)별 권장 적용 가이드.

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

- 동료 엔지니어, 기술 세미나 청중, 인터뷰어를 대상으로 직접 1인칭 발표를 수행하는 **실전 영문 강의 대본(Spoken Technical English)** 제공.
- **표준 4단계 대본 구성**:
  1. **Opening Hook & Problem Statement**: 해당 하드닝 기능이 해결하는 핵심 보안 위협 및 ROP 공격 시나리오 제시.
  2. **Diagram & Architecture Walkthrough**: 다이어그램을 짚어가며 ROP 체인 vs 하드닝 차단 메커니즘 설명.
  3. **Live Demo Commentary**: QEMU 실행 및 실제 ROP Exploit 성공(Base) vs 카나리/하드닝 차단(Hardened) 현장 중계.
  4. **Key Takeaways & Production Advice**: 실무 적용 권고 및 요약.
````

---

## 4. Bilingual Structure Synchronization (다국어 1:1 동기화)

1. **폴더 트리 완전 일치 (`docs_structure: folder`)**:
   - `docs/ko/features/<name>.md`와 `docs/en/features/<name>.md`는 파일명, 섹션 헤더 번호, 다이어그램 참조 위치가 완벽히 일치해야 함.
2. **동일한 기술적 깊이**:
   - 언어 번역에 따른 내용 축약이나 실습 로그 누락을 금지함.

---

## 5. Kernel Build & Scripting Standards (스크립트 표준)

1. **재현 가능성 및 환경 오염 방지**:
   - 모든 스크립트는 `set -euo pipefail`을 선두에 명시하여 예기치 않은 실패 시 즉각 중단되도록 작성함.
   - 빌드 임시 파일은 `build_dir/` 디렉터리 내에 격리하여 호스트 시스템 오염을 방지함.
2. **듀얼 아키텍처 필수 대응**:
   - 아키텍처 분기 시 `ARCH=x86_64` 및 `ARCH=arm64`를 일관되게 지원함.
   - 크로스 컴파일러 접두사(`CROSS_COMPILE=aarch64-linux-gnu-` 등)를 자동 처리함.
3. **`main "$@"` 진입점 구조 의무화**:
   - 모든 셸 스크립트는 상단에 설정 및 모듈화된 서브루틴 함수들을 정의하고, 스크립트의 실행 흐름을 한눈에 파악할 수 있도록 `main "$@"` 구조로 작성함.
   - 절차적 단계(인자 파싱 -> 환경 검증 -> 빌드/생성 -> 산출물 검증)가 `main` 함수 내에 명확히 드러나도록 구현함.
