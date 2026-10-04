/*
 * Dynamic iframe height auto-resizing and theme synchronization
 * Linux Kernel Hardening Lab
 */
(function () {
  'use strict';

  function handleMessage(event) {
    if (!event.data) return;

    // Handle height auto-resizing from child diagrams
    if (event.data.type === 'diagram-resize' && typeof event.data.height === 'number') {
      var iframes = document.querySelectorAll('iframe');
      for (var i = 0; i < iframes.length; i++) {
        var iframe = iframes[i];
        if (iframe.contentWindow === event.source) {
          iframe.style.height = Math.ceil(event.data.height) + 'px';
          break;
        }
      }
    }

    // Handle theme change notifications from child diagrams
    if (event.data.type === 'diagram-theme-change' && event.data.theme) {
      broadcastTheme(event.data.theme);
    }
  }

  function broadcastTheme(theme) {
    var iframes = document.querySelectorAll('iframe');
    iframes.forEach(function (iframe) {
      try {
        if (iframe.contentWindow) {
          iframe.contentWindow.postMessage({ type: 'theme-change', theme: theme }, '*');
          iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: theme }, '*');
        }
      } catch (err) {}
    });
  }

  function getActiveTheme() {
    if (!document.body) return 'dark';
    var scheme = document.body.getAttribute('data-md-color-scheme');
    return scheme === 'default' ? 'light' : 'dark';
  }

  function syncThemeFromMkDocs() {
    broadcastTheme(getActiveTheme());
  }

  function initResizer() {
    if (!document.body) return;

    // Observe MkDocs color scheme attribute changes
    var observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        if (mutations[i].attributeName === 'data-md-color-scheme') {
          syncThemeFromMkDocs();
          break;
        }
      }
    });
    observer.observe(document.body, { attributes: true, attributeFilter: ['data-md-color-scheme'] });

    // Sync theme on initial load
    syncThemeFromMkDocs();

    // Hook load event on all iframes to request resize and sync theme
    document.querySelectorAll('iframe').forEach(function (iframe) {
      iframe.addEventListener('load', function () {
        syncThemeFromMkDocs();
        try {
          if (iframe.contentWindow) {
            iframe.contentWindow.postMessage({ type: 'request-resize' }, '*');
          }
        } catch (err) {}
      });
    });
  }

  window.addEventListener('message', handleMessage);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initResizer);
  } else {
    initResizer();
  }

  // MkDocs Material instant navigation support
  if (typeof location$ !== 'undefined') {
    location$.subscribe(function () {
      setTimeout(function () {
        initResizer();
        document.querySelectorAll('iframe').forEach(function (iframe) {
          try {
            if (iframe.contentWindow) {
              iframe.contentWindow.postMessage({ type: 'request-resize' }, '*');
            }
          } catch (err) {}
        });
      }, 100);
    });
  }
})();
