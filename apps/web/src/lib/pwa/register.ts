/**
 * Register the SendBeam PWA Service Worker (V16-PR05).
 * Safe in all environments (browser, tests, SSR, private browsing).
 */
export function registerServiceWorker(): void {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
    return;
  }

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js', { scope: '/' })
      .then((reg) => {
        // Automatically check for service worker updates periodically
        reg.addEventListener('updatefound', () => {
          const installing = reg.installing;
          if (installing) {
            installing.addEventListener('statechange', () => {
              if (installing.state === 'installed' && navigator.serviceWorker.controller) {
                // New content available
              }
            });
          }
        });
      })
      .catch(() => {
        // Service worker registration failed (e.g. non-HTTPS, disabled in browser settings)
      });
  });
}

/**
 * Notify the Service Worker that an active file transfer has started.
 * Prevents disruptive service worker updates from evicting active transfer state.
 */
export function notifyTransferStart(): void {
  if (typeof navigator !== 'undefined' && navigator.serviceWorker?.controller) {
    navigator.serviceWorker.controller.postMessage({ type: 'TRANSFER_START' });
  }
}

/**
 * Notify the Service Worker that an active file transfer has settled.
 */
export function notifyTransferEnd(): void {
  if (typeof navigator !== 'undefined' && navigator.serviceWorker?.controller) {
    navigator.serviceWorker.controller.postMessage({ type: 'TRANSFER_END' });
  }
}
