import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';
import { describe, expect, it, vi } from 'vitest';

const swPath = resolve(__dirname, '../public/sw.js');
const swCode = readFileSync(swPath, 'utf8');

class MockCache {
  readonly store = new Map<string, Response>();
  constructor(readonly name: string) {}

  async match(req: RequestInfo | URL): Promise<Response | undefined> {
    const key = typeof req === 'string' ? req : 'url' in req ? req.url : req.toString();
    return this.store.get(key);
  }

  async put(req: RequestInfo | URL, res: Response): Promise<void> {
    const key = typeof req === 'string' ? req : 'url' in req ? req.url : req.toString();
    this.store.set(key, res);
  }

  async addAll(urls: string[]): Promise<void> {
    for (const u of urls) {
      this.store.set(u, new Response('ok', { status: 200 }));
    }
  }

  async delete(req: RequestInfo | URL): Promise<boolean> {
    const key = typeof req === 'string' ? req : 'url' in req ? req.url : req.toString();
    return this.store.delete(key);
  }
}

class MockCacheStorage {
  readonly caches = new Map<string, MockCache>();

  async open(name: string): Promise<MockCache> {
    if (!this.caches.has(name)) {
      this.caches.set(name, new MockCache(name));
    }
    return this.caches.get(name)!;
  }

  async keys(): Promise<string[]> {
    return Array.from(this.caches.keys());
  }

  async delete(name: string): Promise<boolean> {
    return this.caches.delete(name);
  }

  async match(req: RequestInfo | URL): Promise<Response | undefined> {
    for (const cache of this.caches.values()) {
      const res = await cache.match(req);
      if (res) return res;
    }
    return undefined;
  }
}

interface MockExtendableEvent {
  waitUntil: (p: Promise<unknown>) => void;
}

interface MockFetchEvent {
  request: Request;
  respondWith: (r: Response | Promise<Response>) => void;
}

interface MockMessageEvent {
  data: unknown;
  ports?: readonly { postMessage: (msg: unknown) => void }[];
}

interface SWMockEnvironment {
  dispatchInstall: (ev: MockExtendableEvent) => void;
  dispatchActivate: (ev: MockExtendableEvent) => void;
  dispatchFetch: (ev: MockFetchEvent) => void;
  dispatchMessage: (ev: MockMessageEvent) => void;
  mockCaches: MockCacheStorage;
  skipWaiting: ReturnType<typeof vi.fn>;
  claim: ReturnType<typeof vi.fn>;
  sandbox: Record<string, unknown>;
}

function setupSWEnvironment(initialCaches: string[] = []): SWMockEnvironment {
  const listeners: Record<string, ((ev: unknown) => void)[]> = {};
  const mockCaches = new MockCacheStorage();
  for (const c of initialCaches) {
    mockCaches.caches.set(c, new MockCache(c));
  }

  const skipWaiting = vi.fn().mockResolvedValue(undefined);
  const claim = vi.fn().mockResolvedValue(undefined);

  const selfObj = {
    addEventListener: (type: string, cb: (ev: unknown) => void) => {
      if (!listeners[type]) listeners[type] = [];
      listeners[type].push(cb);
    },
    location: { origin: 'https://sendbeam.test' },
    clients: { claim },
    skipWaiting,
  };

  const sandbox: Record<string, unknown> = {
    self: selfObj,
    caches: mockCaches,
    fetch: vi.fn().mockImplementation(async () => {
      return new Response('network-ok', { status: 200 });
    }),
    URL,
    Response,
    Request,
    Set,
    Map,
    Promise,
    Math,
  };

  vm.createContext(sandbox);
  vm.runInContext(swCode, sandbox);

  return {
    dispatchInstall: (ev: MockExtendableEvent) => listeners['install']?.[0]?.(ev),
    dispatchActivate: (ev: MockExtendableEvent) => listeners['activate']?.[0]?.(ev),
    dispatchFetch: (ev: MockFetchEvent) => listeners['fetch']?.[0]?.(ev),
    dispatchMessage: (ev: MockMessageEvent) => listeners['message']?.[0]?.(ev),
    mockCaches,
    skipWaiting,
    claim,
    sandbox,
  };
}

describe('PWA Service Worker allowlisted caching and isolation', () => {
  it('precaches only owned shell assets on install', async () => {
    const { dispatchInstall, mockCaches, skipWaiting } = setupSWEnvironment();

    let installWait: Promise<unknown> | undefined;
    dispatchInstall({
      waitUntil: (p: Promise<unknown>) => {
        installWait = p;
      },
    });

    await installWait;
    expect(mockCaches.caches.has('sendbeam-shell-v1')).toBe(true);

    const shellCache = mockCaches.caches.get('sendbeam-shell-v1')!;
    expect(await shellCache.match('/')).toBeDefined();
    expect(await shellCache.match('/index.html')).toBeDefined();
    expect(await shellCache.match('/manifest.webmanifest')).toBeDefined();
    expect(await shellCache.match('/favicon.svg')).toBeDefined();
    expect(await shellCache.match('/icons/icon-192.png')).toBeDefined();

    expect(skipWaiting).toHaveBeenCalled();
  });

  it('preserves unrelated caches on activation while pruning older sendbeam-shell versions', async () => {
    const { dispatchActivate, mockCaches, claim } = setupSWEnvironment([
      'unrelated-app-cache',
      'user-download-cache',
      'sendbeam-shell-v0',
      'sendbeam-shell-v1',
    ]);

    let activateWait: Promise<unknown> | undefined;
    dispatchActivate({
      waitUntil: (p: Promise<unknown>) => {
        activateWait = p;
      },
    });

    await activateWait;

    const remainingKeys = await mockCaches.keys();
    // Unrelated caches must NOT be deleted
    expect(remainingKeys).toContain('unrelated-app-cache');
    expect(remainingKeys).toContain('user-download-cache');
    // Current shell cache must be retained
    expect(remainingKeys).toContain('sendbeam-shell-v1');
    // Older SendBeam shell cache must be pruned
    expect(remainingKeys).not.toContain('sendbeam-shell-v0');

    expect(claim).toHaveBeenCalled();
  });

  it('caches allowlisted shell assets in Stale-While-Revalidate mode', async () => {
    const { dispatchFetch, mockCaches } = setupSWEnvironment();

    const allowedUrls = [
      'https://sendbeam.test/assets/index-abc12345.js',
      'https://sendbeam.test/assets/index-def67890.css',
      'https://sendbeam.test/icons/icon-192.png',
      'https://sendbeam.test/favicon.svg',
      'https://sendbeam.test/manifest.webmanifest',
      'https://sendbeam.test/index.html',
    ];

    for (const url of allowedUrls) {
      let respondPromise: Promise<Response> | undefined;
      const req = new Request(url, { method: 'GET' });
      dispatchFetch({
        request: req,
        respondWith: (p: Response | Promise<Response>) => {
          respondPromise = Promise.resolve(p);
        },
      });

      expect(respondPromise).toBeDefined();
      const response = await respondPromise!;
      expect(response.status).toBe(200);

      // Wait a microtask tick for the background cache.put promise to resolve
      await new Promise((r) => setTimeout(r, 10));

      const shellCache = await mockCaches.open('sendbeam-shell-v1');
      const cached = await shellCache.match(req);
      expect(cached).toBeDefined();
    }
  });

  it('strictly bypasses dynamic endpoints, query parameters, signaling, and sw.js from cache', async () => {
    const { dispatchFetch, mockCaches } = setupSWEnvironment();

    const nonAllowlisted = [
      // Dynamic room / invite requests with query parameters
      'https://sendbeam.test/?code=7-alpha-bravo',
      'https://sendbeam.test/index.html?code=888-mobile',
      'https://sendbeam.test/room/123-abc',
      'https://sendbeam.test/api/transfer/status',
      'https://sendbeam.test/arbitrary/data/file.bin',
      // Signaling and operational endpoints
      'https://sendbeam.test/ws',
      'https://sendbeam.test/ws/peer-123',
      'https://sendbeam.test/config.json',
      'https://sendbeam.test/healthz',
      'https://sendbeam.test/metrics',
      // Service worker itself
      'https://sendbeam.test/sw.js',
    ];

    for (const url of nonAllowlisted) {
      const req = new Request(url, { method: 'GET' });
      dispatchFetch({
        request: req,
        respondWith: () => {},
      });

      // Navigation requests to ?code=... respond with fallback to clean app shell,
      // but must NOT cache the ?code=... request itself in CacheStorage
      const shellCache = await mockCaches.open('sendbeam-shell-v1');
      const cached = await shellCache.match(req);
      expect(cached).toBeUndefined();
    }
  });

  it('strictly bypasses Range requests and cross-origin requests', async () => {
    const { dispatchFetch, mockCaches } = setupSWEnvironment();

    // Range request on same-origin asset
    let rangeResponded = false;
    const rangeReq = new Request('https://sendbeam.test/assets/large.dat', {
      headers: { range: 'bytes=0-1024' },
    });
    dispatchFetch({
      request: rangeReq,
      respondWith: () => {
        rangeResponded = true;
      },
    });
    expect(rangeResponded).toBe(false);

    // Cross-origin request
    let foreignResponded = false;
    const foreignReq = new Request('https://external-cdn.com/assets/lib.js');
    dispatchFetch({
      request: foreignReq,
      respondWith: () => {
        foreignResponded = true;
      },
    });
    expect(foreignResponded).toBe(false);

    const shellCache = await mockCaches.open('sendbeam-shell-v1');
    expect(await shellCache.match(rangeReq)).toBeUndefined();
    expect(await shellCache.match(foreignReq)).toBeUndefined();
  });

  it('coordinates updates during active transfers and defers skipWaiting until settled', async () => {
    const { dispatchInstall, dispatchMessage, skipWaiting } = setupSWEnvironment();

    // Client signals active transfer started
    dispatchMessage({
      data: { type: 'TRANSFER_START' },
    });

    // Verify status query reports active transfer
    let statusMsg:
      { activeTransfers: number; cacheName: string; waitingToActivate: boolean } | undefined;
    dispatchMessage({
      data: { type: 'GET_STATUS' },
      ports: [
        {
          postMessage: (msg: unknown) => {
            statusMsg = msg as {
              activeTransfers: number;
              cacheName: string;
              waitingToActivate: boolean;
            };
          },
        },
      ],
    });
    expect(statusMsg).toEqual({
      activeTransfers: 1,
      cacheName: 'sendbeam-shell-v1',
      waitingToActivate: false,
    });

    // Install event occurs while transfer is running
    skipWaiting.mockClear();
    let installWait: Promise<unknown> | undefined;
    dispatchInstall({
      waitUntil: (p: Promise<unknown>) => {
        installWait = p;
      },
    });
    await installWait;

    // skipWaiting must NOT be called while activeTransfers > 0
    expect(skipWaiting).not.toHaveBeenCalled();

    // An unforced SKIP_WAITING from client is also deferred
    dispatchMessage({
      data: { type: 'SKIP_WAITING', force: false },
    });
    expect(skipWaiting).not.toHaveBeenCalled();

    // Active transfer settles
    dispatchMessage({
      data: { type: 'TRANSFER_END' },
    });

    // Now skipWaiting must have been invoked to complete activation cleanly
    expect(skipWaiting).toHaveBeenCalledTimes(1);
  });
});
