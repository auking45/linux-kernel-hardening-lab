/*
 * Starlight Bridge: Syncs Starlight's [data-theme="dark"|"light"] with
 * embedded interactive HTML diagrams (iframe postMessage) and auto-resizes heights.
 */
(function () {
  'use strict';

  function getActiveTheme() {
    var theme = document.documentElement.getAttribute('data-theme');
    return theme === 'light' ? 'light' : 'dark';
  }

  function broadcastTheme(theme) {
    document.querySelectorAll('iframe').forEach(function (iframe) {
      try {
        if (iframe.contentWindow) {
          iframe.contentWindow.postMessage({ type: 'theme-change', theme: theme }, '*');
          iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: theme }, '*');
        }
      } catch (e) {}
    });
  }

  window.addEventListener('message', function (event) {
    if (!event.data) return;
    if (event.data.type === 'diagram-resize' && typeof event.data.height === 'number') {
      document.querySelectorAll('iframe').forEach(function (iframe) {
        if (iframe.contentWindow === event.source) {
          iframe.style.height = Math.ceil(event.data.height) + 'px';
        }
      });
    }
    if (event.data.type === 'diagram-theme-change' && event.data.theme) {
      broadcastTheme(event.data.theme);
    }
  });

  function initBridge() {
    var observer = new MutationObserver(function () {
      broadcastTheme(getActiveTheme());
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });

    broadcastTheme(getActiveTheme());

    document.querySelectorAll('iframe').forEach(function (iframe) {
      iframe.addEventListener('load', function () {
        broadcastTheme(getActiveTheme());
        try {
          if (iframe.contentWindow) {
            iframe.contentWindow.postMessage({ type: 'request-resize' }, '*');
          }
        } catch (e) {}
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBridge);
  } else {
    initBridge();
  }
})();

