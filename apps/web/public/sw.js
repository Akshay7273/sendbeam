/**
 * SendBeam Minimal PWA Service Worker (V16-PR05)
 *
 * Implements an offline-installable app shell while strictly enforcing:
 * - TRANSFERS STAY ONLINE-ONLY: Never cache WebSocket (/ws), WebRTC signaling,
 *   /config.json, Range requests, or transfer data streams.
 * - Stale-while-revalidate for local static assets (/assets/*, /icons/*).
 * - Fast app shell loading and automatic client claiming.
 */

const CACHE_NAME = 'sendbeam-shell-v1';

const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icons/icon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-192.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') {
    return;
  }

  const url = new URL(req.url);

  // 1. Strict online-only bypass: WebSocket signaling, dynamic configs, health endpoints
  if (
    url.pathname === '/ws' ||
    url.pathname.startsWith('/ws/') ||
    url.pathname === '/config.json' ||
    url.pathname === '/healthz' ||
    url.pathname === '/metrics' ||
    url.protocol === 'ws:' ||
    url.protocol === 'wss:' ||
    req.headers.has('range')
  ) {
    return;
  }

  // 2. Navigation requests: Network-first with fallback to cached app shell
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(async () => {
        const cached = await caches.match('/index.html');
        if (cached) return cached;
        return caches.match('/');
      }),
    );
    return;
  }

  // 3. Same-origin static assets: Stale-While-Revalidate
  if (url.origin === self.location.origin) {
    event.respondWith(
      caches.open(CACHE_NAME).then(async (cache) => {
        const cached = await cache.match(req);
        const fetchPromise = fetch(req)
          .then((networkRes) => {
            if (networkRes && networkRes.status === 200) {
              cache.put(req, networkRes.clone());
            }
            return networkRes;
          })
          .catch(() => cached);

        return cached || fetchPromise;
      }),
    );
  }
});
