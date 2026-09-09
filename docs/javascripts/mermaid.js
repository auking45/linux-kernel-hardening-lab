// Dynamic Mermaid.js Loader and Renderer for Material for MkDocs
let mermaidModule = null;

async function getMermaid() {
  if (!mermaidModule) {
    const mod = await import("https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs");
    mermaidModule = mod.default;
  }
  return mermaidModule;
}

function getThemeConfig() {
  const scheme = document.body.getAttribute("data-md-color-scheme");
  const isDark = scheme === "slate" || (!scheme && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);

  if (isDark) {
    return {
      theme: "dark",
      themeVariables: {
        darkMode: true,
        background: "#1e293b",
        primaryColor: "#334155",
        primaryTextColor: "#f8fafc",
        primaryBorderColor: "#64748b",
        lineColor: "#94a3b8",
        secondaryColor: "#1e293b",
        tertiaryColor: "#0f172a",
        noteBkgColor: "#1e293b",
        noteTextColor: "#f8fafc",
        noteBorderColor: "#64748b",
        actorBkg: "#334155",
        actorTextColor: "#f8fafc",
        actorLineColor: "#94a3b8",
        signalColor: "#f8fafc",
        signalTextColor: "#f8fafc",
        labelTextColor: "#f8fafc",
        nodeTextColor: "#f8fafc"
      }
    };
  }

  return {
    theme: "default",
    themeVariables: {
      darkMode: false,
      primaryColor: "#e2e8f0",
      primaryTextColor: "#0f172a",
      primaryBorderColor: "#475569",
      lineColor: "#64748b",
      secondaryColor: "#f8fafc",
      tertiaryColor: "#ffffff",
      noteBkgColor: "#fef3c7",
      noteTextColor: "#78350f",
      noteBorderColor: "#f59e0b",
      actorBkg: "#e2e8f0",
      actorTextColor: "#0f172a",
      actorLineColor: "#475569",
      signalColor: "#334155",
      signalTextColor: "#0f172a",
      labelTextColor: "#0f172a",
      nodeTextColor: "#0f172a"
    }
  };
}

async function renderMermaidDiagrams() {
  const codeBlocks = document.querySelectorAll("pre.mermaid > code");
  if (codeBlocks.length === 0) {
    return;
  }

  try {
    const mermaid = await getMermaid();
    const themeConfig = getThemeConfig();

    mermaid.initialize({
      startOnLoad: false,
      theme: themeConfig.theme,
      themeVariables: themeConfig.themeVariables,
      securityLevel: "loose",
      suppressErrorRendering: true,
      htmlLabels: true
    });

    let index = 0;
    for (const codeEl of codeBlocks) {
      const pre = codeEl.parentElement;
      if (pre.dataset.mermaidRendered === "true") {
        continue;
      }

      const rawText = codeEl.textContent.trim();
      const renderId = `mermaid-svg-${Date.now()}-${index++}`;

      try {
        const { svg } = await mermaid.render(renderId, rawText);
        const container = document.createElement("div");
        container.className = "mermaid-container";
        container.style.display = "flex";
        container.style.justifyContent = "center";
        container.style.margin = "1.5em 0";
        container.style.overflowX = "auto";
        container.innerHTML = svg;

        pre.dataset.mermaidRendered = "true";
        pre.parentNode.insertBefore(container, pre);
        pre.style.display = "none";
      } catch (err) {
        console.error("Mermaid rendering error for block:", err);
        const errEl = document.getElementById(`d${renderId}`);
        if (errEl) {
          errEl.remove();
        }
        pre.style.display = "block";
      }
    }
  } catch (err) {
    console.error("Failed to load or execute Mermaid:", err);
  }
}

// Hook into MkDocs Material page navigation & theme switch events
if (typeof document$ !== "undefined") {
  document$.subscribe(() => {
    document.querySelectorAll("pre.mermaid").forEach(pre => {
      const prev = pre.previousElementSibling;
      if (prev && prev.classList.contains("mermaid-container")) {
        prev.remove();
      }
      delete pre.dataset.mermaidRendered;
    });

    document.querySelectorAll("div[id^='dmermaid-svg-']").forEach(el => el.remove());
    renderMermaidDiagrams();
  });
} else {
  document.addEventListener("DOMContentLoaded", renderMermaidDiagrams);
}

