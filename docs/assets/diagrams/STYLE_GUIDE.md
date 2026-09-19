# Architecture Diagrams: Dynamic Flow & Visual Design System (v2.0)

본 문서는 `linux-kernel-hardening-lab`의 모든 인터랙티브 보안 아키텍처 다이어그램(`docs/assets/diagrams/*/architecture.html`)에 적용되는 **동적 흐름 시각화 및 스타일 표준 규격(Design System Guide)**입니다.

---

## 1. 핵심 철학: "움직이는 제어 흐름과 즉각적인 방어 차단"

커널 하드닝은 정적인 메모리 레이아웃 설명에 그쳐서는 안 되며, **실제 공격자의 익스플로잇 제어 흐름(Control Flow)**과 **하드웨어/커널 방어선에서의 실시간 가로챔(Intercept) 및 차단(Detonation)**을 사용자가 직관적으로 체감할 수 있어야 합니다.

```
[출발지 노드] ──(동적 펄스 스트림)──> [MMU / 하드웨어 가드] ──(⛔ 차단 트랩 충돌)──> [커널 Oops / 패닉]
                                            │ (차단 실패 시)
                                            ▼
                                  [타겟 쉘코드 / 권한 탈취]
```

---

## 2. 디자인 토큰 및 테마 색상 (Design Tokens)

다크 모드를 기본값으로 하며, 라이트 모드 전환 시에도 일관된 색상 대비와 가시성을 제공합니다.

| 토큰 | Dark Mode Hex | Light Mode Hex | 의미 및 용도 |
| :--- | :--- | :--- | :--- |
| `--bg-color` | `#0b132b` | `#f1f5f9` | 전체 캔버스 배경 |
| `--card-bg` | `#1c2541` | `#ffffff` | 컴포넌트 패널 및 카드 배경 |
| `--card-border`| `#3a506b` | `#cbd5e1` | 패널 외곽선 경계 |
| `--accent-blue` | `#38bdf8` | `#0284c7` | 커널 영역(Ring 0 / EL1), 정상 디스패치 |
| `--accent-green`| `#22c55e` | `#16a34a` | 정상 리턴(Sysret), 방어 성공, 무결성 통과 |
| `--accent-red` | `#ef4444` | `#dc2626` | 공격 흐름, 하이잭된 포인터, 유저 쉘코드 침투 |
| `--accent-yellow`| `#f59e0b`| `#d97706` | MMU 차단선, 검증 진행 중, 트랩 감지 |
| `--perm-user` | `#fb923c` | `#ea580c` | 유저 공간(Ring 3 / EL0) |

---

## 3. 동적 SVG 애니메이션 표준 규격 (Dynamic SVG Standards)

모든 다이어그램은 외부 라이브러리(D3, Three.js 등) 없이 **순수 HTML5 + SVG + CSS3 + 바닐라 JavaScript**로 완결되어야 합니다.

### 3.1 동적 대시 플로우 (Flowing Dashed Path)
연결선 위로 신호가 이동하는 방향성을 시각화합니다.
```css
@keyframes flowDash {
  to { stroke-dashoffset: -48; }
}

.flow-path {
  stroke-dasharray: 8 6;
  animation: flowDash 1.2s linear infinite;
}

.flow-path.normal {
  stroke: var(--accent-blue);
}

.flow-path.attack {
  stroke: var(--accent-red);
  animation-duration: 0.8s;
  filter: drop-shadow(0 0 6px var(--accent-red));
}

.flow-path.blocked {
  stroke: var(--accent-yellow);
  stroke-dasharray: 6 4;
}
```

### 3.2 경로 추적 펄스 파티클 (Moving Pulse Particle)
SVG `<animateMotion>`을 활용하여 베지어 곡선 경로를 따라 고속 이동하는 신호 펄스를 렌더링합니다.
```html
<path id="attackStream" d="M 200 180 C 200 240 400 250 400 345" fill="none" class="flow-path attack" />
<circle r="7" fill="#ef4444" filter="url(#glow-red)" class="flow-particle">
  <animateMotion dur="1.5s" repeatCount="indefinite" path="M 200 180 C 200 240 400 250 400 345" />
</circle>
```

### 3.3 차단점 폭발/충돌 효과 (Trap Detonation Ripples)
하드웨어 경계(MMU SMEP/PXN, BTI, PAC, KPTI 등)에서 공격이 가로막히는 순간, 동심원 충격파를 방출합니다.
```css
@keyframes rippleExpand {
  0% { r: 6px; opacity: 1; }
  100% { r: 38px; opacity: 0; }
}

.trap-ripple {
  animation: rippleExpand 1.5s cubic-bezier(0, 0.2, 0.8, 1) infinite;
}
```

---

## 4. 필수 컨트롤 툴바 규격 (`.sim-toolbar`)

사용자가 제어 흐름을 직접 조작하고 관찰할 수 있도록 모든 다이어그램 상단에 컨트롤 툴바를 배치합니다:
1. **재생 / 일시정지 버튼 (`#playBtn`)**:
   - 클릭 시 애니메이션 정지(`animation-play-state: paused`) 및 재생 전환.
2. **초기화 버튼 (`resetAnimation`)**:
   - 신호 흐름을 시작 시점으로 리셋.
3. **배속 조절 (`0.5x`, `1.0x`, `1.5x`)**:
   - 슬로우 모션(0.5x)으로 정밀 분석 또는 고속(1.5x) 시뮬레이션 지원.
4. **실시간 상태 표시등 (`.sim-status` & `.status-dot`)**:
   - 현재 시나리오의 방어 상태(정상: Green, 공격 침투: Red, 차단 활성: Yellow)를 실시간 텍스트 및 점멸 LED로 표시.

---

## 5. 시나리오 구성 4단계 템플릿

각 다이어그램은 반드시 다음 4개 탭을 제공해야 합니다:
1. **Tab 1 (Normal Model)**: 취약점 없는 합법적 시스템 동작 및 제어 흐름.
2. **Tab 2 (Exploit Attack Vector)**: 방어가 해제된 베이스라인 환경에서의 침투 및 권한 탈취 흐름.
3. **Tab 3 (Hardware / Kernel Defense)**: 하드닝 활성화 시 하드웨어/메커니즘 차단 및 커널 트랩 동작.
4. **Tab 4 (Comparison & Matrix)**: 공격 성공률, 런타임 오버헤드, 공격자의 우회 기법 전이 비교.

