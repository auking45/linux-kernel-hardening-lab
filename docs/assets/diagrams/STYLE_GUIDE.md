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

---

## 6. 캔버스 규격 및 iframe 높이 자동 동기화 표준 (Zero-Void & Zero-Scroll)

다이어그램이 임베드된 문서에서 **내부 세로 스크롤바가 발생하지 않고(Zero-Scroll)**, 카드 하단에 **불필요한 빈 여백 공간이 남지 않도록(Zero-Void)** 다음 아키텍처 규칙을 필수로 준수해야 합니다.

### 6.1 DOM 래퍼 및 CSS 초기화 표준
- `html, body`는 마진/패딩을 완전히 제거하고 `overflow: hidden` 처리함.
- 모든 시각적 컨텐츠(헤더, 컨트롤, 캔버스 카드, 설명 박스)는 반드시 `<div class="diagram-canvas" id="diagramCanvas">` 직하위에 포함함.
- 최하단 요소의 `margin-bottom`이 캔버스 밖으로 여백을 누적시키지 않도록 주의함.

```css
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  margin: 0;
  padding: 0;
  overflow: hidden;
  background: var(--bg);
}
body {
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  transition: background 0.3s, color 0.3s;
}
.diagram-canvas {
  padding: 20px;
  box-sizing: border-box;
  overflow: hidden;
}
```

### 6.2 정밀 높이 측정 및 피드백 루프 원천 차단
- `reportHeight()`는 반드시 `#diagramCanvas`의 순수 렌더링 높이(`getBoundingClientRect().height`)를 측정하여 `window.parent`로 전송함.
- **절대 금지**: `Math.max(documentElement.scrollHeight, documentElement.offsetHeight, ...)`
  - iframe 내부에서 `documentElement.offsetHeight`는 **iframe 자체의 현재 뷰포트 높이**를 반환하므로, 부모 창이 여백을 더할 때마다 높이가 끝없이 팽창하는 양의 피드백 루프(Positive Feedback Loop)를 유발함.

```javascript
function reportHeight() {
  const canvas = document.getElementById('diagramCanvas');
  if (!canvas) return;
  const h = Math.ceil(canvas.getBoundingClientRect().height);
  if (h > 0 && window.parent && window.parent !== window) {
    window.parent.postMessage({ type: 'diagram-resize', height: h }, '*');
  }
}
```

### 6.3 관측 대상 격리 (`ResizeObserver`)
- `ResizeObserver`의 관측 대상은 **반드시 `#diagramCanvas`**여야 함.
- `document.body`를 관측할 경우, 부모 창의 iframe 크기 변경이 자식 창 body의 resize 이벤트로 전파되어 무한 루프가 발생함.
- 내부 탭 전환, 스텝 변경, 텍스트 줄바꿈 시 즉시 `reportHeight()`를 호출하거나 `setTimeout(reportHeight, 30)`을 통해 재계산함.

```javascript
window.addEventListener('load', reportHeight);
window.addEventListener('resize', reportHeight);
if (window.ResizeObserver) {
  const canvas = document.getElementById('diagramCanvas');
  if (canvas) {
    new ResizeObserver(function() {
      reportHeight();
    }).observe(canvas);
  }
}
```

### 6.4 부모-자식 테마 및 리사이즈 메시지 핸들러
```javascript
window.addEventListener('message', function(event) {
  if (event.data && (event.data.type === 'theme-change' || event.data.type === 'set-diagram-theme')) {
    applyTheme(event.data.theme);
  } else if (event.data && event.data.type === 'request-resize') {
    reportHeight();
  }
});
```

### 6.5 마크다운 문서 내 iframe 임베드 표준 템플릿
- 인위적인 `min-height`를 지정하지 않아야 컨텐츠 크기에 맞게 자동으로 수축/팽창함.
- `onload` 시점에도 `#diagramCanvas` 높이를 즉시 바인딩하도록 인라인 스크립트를 포함함.

```html
<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/<feature>/<name>.html"
    style="width: 100%; border: none; display: block; overflow: hidden;"
    scrolling="no"
    onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"
  ></iframe>
</div>
```

---

## 7. 다이어그램 작성 시 안티패턴 체크리스트 (Anti-Patterns Checklist)

| 금지 사항 (Anti-Pattern) | 원인 및 문제점 | 올바른 표준 (Standard) |
| :--- | :--- | :--- |
| `min-height: 680px` 또는 `height: 450px` 강제 | 컴팩트한 다이어그램 하단에 불필요한 거대 공백 형성 | 고정/최소 높이 제거, `#diagramCanvas` 순수 높이 동기화 |
| `documentElement.offsetHeight` 측정 | iframe 뷰포트 높이가 반환되어 지속적인 높이 팽창 루프 유발 | `diagramCanvas.getBoundingClientRect().height` 측정 |
| `ResizeObserver(document.body)` | 부모 창의 리사이즈가 body 리사이즈를 트리거하여 재귀 루프 발생 | `ResizeObserver(diagramCanvas)`로 내부 컨텐츠 변화만 감지 |
| 부모 `iframe-resizer.js`에서 임의의 패딩 가산 (`+ 24px`) | 다이어그램 하단에 오차 여백 누적 | `Math.ceil(event.data.height) + 'px'` 정확한 픽셀 단위 매핑 |
| 외부 무거운 JS 라이브러리(D3/Three.js) 의존 | 로딩 지연 및 MkDocs 정적 빌드 충돌 가능성 | 순수 HTML5 + SVG + 바닐라 JavaScript 독립 구동 |


