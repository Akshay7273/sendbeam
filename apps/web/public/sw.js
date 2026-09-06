/**
 * SendBeam PWA Service Worker (V18H-PR03)
 *
 * Implements an allowlisted offline app shell while strictly enforcing:
 * - TRANSFERS STAY ONLINE-ONLY: Never cache WebSocket (/ws), WebRTC signaling,
 *   /config.json, Range requests, or transfer data streams.
 * - Shell-only caching: Only cache verified, owned static shell assets
 *   (/assets/*, /icons/*, precached shell files). Never cache arbitrary endpoints,
 *   invite URLs, or query parameters.
 * - Cache isolation: Only prune SendBeam's own older cache versions (sendbeam-shell-*)
 *   during activation. Never delete unrelated caches on the origin.
 * - Active-transfer coordination: Defer disruptive updates while file transfers are active.
 */

const CACHE_PREFIX = 'sendbeam-shell-';
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

const ALLOWED_EXACT_SHELL_PATHS = new Set([
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/favicon.svg',
]);

const ALLOWED_SHELL_PREFIXES = ['/assets/', '/icons/'];

/**
 * Validates whether a URL represents an owned static shell asset eligible for caching.
 * Enforces a strict allowlist — arbitrary paths, invite links, and query parameters
 * are never cached.
 */
function isAllowedShellAsset(url) {
  // Only same-origin requests can be shell assets
  if (url.origin !== self.location.origin) {
    return false;
  }

  // Never cache requests with query strings (invite codes, room tokens, params)
  if (url.search) {
    return false;
  }

  // Never cache the service worker itself
  if (url.pathname === '/sw.js') {
    return false;
  }

  // Match exact root shell assets
  if (ALLOWED_EXACT_SHELL_PATHS.has(url.pathname)) {
    return true;
  }

  // Match allowlisted static asset directory prefixes (Vite immutable builds, icons)
  for (const prefix of ALLOWED_SHELL_PREFIXES) {
    if (url.pathname.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

// Active transfer tracking and client coordination
let activeTransfers = 0;
let waitingToActivate = false;

self.addEventListener('message', (event) => {
  if (!event.data || typeof event.data !== 'object') {
    return;
  }

  switch (event.data.type) {
    case 'TRANSFER_START':
      activeTransfers++;
      break;

    case 'TRANSFER_END':
      activeTransfers = Math.max(0, activeTransfers - 1);
      if (activeTransfers === 0 && waitingToActivate) {
        waitingToActivate = false;
        self.skipWaiting();
      }
      break;

    case 'SKIP_WAITING':
      if (activeTransfers === 0 || event.data.force) {
        waitingToActivate = false;
        self.skipWaiting();
      } else {
        waitingToActivate = true;
      }
      break;

    case 'GET_STATUS':
      if (event.ports && event.ports[0]) {
        event.ports[0].postMessage({
          activeTransfers,
          cacheName: CACHE_NAME,
          waitingToActivate,
        });
      }
      break;
  }
});

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_ASSETS))
      .then(async () => {
        // If an active transfer is currently running, defer skipWaiting to prevent disruption
        if (activeTransfers === 0) {
          await self.skipWaiting();
        } else {
          waitingToActivate = true;
        }
      }),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME)
            .map((key) => caches.delete(key)),
        ),
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

  // 1. Strict online-only bypass: WebSocket signaling, dynamic configs, health/metrics, Range requests
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

  // 2. Navigation requests: Network-first with fallback to clean cached app shell
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

  // 3. Allowlisted shell assets: Stale-While-Revalidate
  // Strictly applies ONLY to verified owned static shell assets (no query strings, no dynamic paths)
  if (isAllowedShellAsset(url)) {
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
    return;
  }

  // 4. Any other request is deliberately NOT intercepted by the service worker,
  // falling through to standard browser network handling without polluting the cache.
});
