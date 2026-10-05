# Linux Kernel Hardening Lab - AI Agent Guidelines (`AGENTS.md`)

본 문서는 **Linux Kernel Hardening Lab** 리포지토리에서 작업하는 모든 AI 에이전트(Antigravity 등)가 반드시 준수해야 하는 **핵심 프로젝트 규칙 및 엔지니어링 표준 지시서**임.

---

## 1. 🇰🇷 한국어 기술 문서 작성 규칙 (명사 종결형 엄격 준수)

- **존댓말 사용 절대 금지**: "~합니다", "~했습니다", "~됩니다", "~바랍니다" 등의 경어체 사용을 엄격히 금지함.
- **구어체 평서문 지양**: "~다", "~한다", "~이다" 등의 어미를 지양함.
- **간결한 개조식 명사 종결형 필수**: 문장 종결 시 반드시 **"~함", "~임", "~수행", "~제공", "~차단", "~비교", 명사구**로 끝맺어야 함.
- **국/영문 대칭성(Parity)**: 모든 신규 문서 및 시나리오는 한국어(`docs/ko/`)와 영어(`docs/en/`)에 1:1 대칭으로 작성되어야 함.

---

## 2. 🎨 인터랙티브 아키텍처 다이어그램 표준 (Zero-Void & Zero-Scroll)

신규 인터랙티브 다이어그램(`docs/assets/diagrams/*/*.html`)을 제작하거나 수정할 때는 다음 규칙을 **필수적으로 준수**하여 내부 세로 스크롤바와 하단 빈 공간(Void)을 원천 차단함:

### 2.1 HTML/CSS 구조 규격
- `html, body`는 마진/패딩 0, `overflow: hidden`, `background: var(--bg)` 적용.
- 모든 시각적 컨텐츠는 반드시 `<div class="diagram-canvas" id="diagramCanvas">` 직하위에 포함함:
  ```css
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { margin: 0; padding: 0; overflow: hidden; background: var(--bg); }
  .diagram-canvas { padding: 20px; box-sizing: border-box; overflow: hidden; }
  ```

### 2.2 높이 측정 및 피드백 루프 원천 차단
- `reportHeight()`는 반드시 `#diagramCanvas`의 순수 렌더링 높이를 측정함:
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
- **절대 금지**: `Math.max(documentElement.scrollHeight, documentElement.offsetHeight, ...)`
  - iframe 내부에서 `documentElement.offsetHeight`는 뷰포트 높이를 반환하므로 부모의 리사이즈와 결합 시 끝없는 팽창 루프(Positive Feedback Loop)가 발생함.
- **관측 대상 격리**: `ResizeObserver`는 `document.body`가 아닌 **`document.getElementById('diagramCanvas')`만 관측**함.

### 2.3 마크다운 본문 iframe 임베드 표준
- `min-height`를 인위적으로 지정하지 않으며, `onload` 시 `#diagramCanvas` 높이를 즉시 계산하도록 작성함:
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

## 3. 🧪 문서 빌드 검증 필수 절차

모든 문서 작성 및 다이어그램 수정 후에는 반드시 strict 모드 빌드를 수행하여 경고 및 오류가 0건임을 확인해야 함:
```bash
.venv/bin/mkdocs build --strict
```

---

## 4. 📚 상세 표준 문서 참조

- 종합 엔지니어링 표준: [SKILL.md](file:///home/auking45/repos/linux-kernel-hardening-lab/SKILL.md)
- 다이어그램 디자인 시스템 가이드: [docs/assets/diagrams/STYLE_GUIDE.md](file:///home/auking45/repos/linux-kernel-hardening-lab/docs/assets/diagrams/STYLE_GUIDE.md)

