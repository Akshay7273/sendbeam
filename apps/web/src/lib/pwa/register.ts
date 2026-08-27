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
