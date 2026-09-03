import { describe, expect, it, vi } from 'vitest';
import {
  isDirectFileSystemSupported,
  isPersistentTrustSupported,
  isStorageQuotaSupported,
  isWakeLockSupported,
  isWebShareSupported,
  probeStorageCapabilities,
} from './capability.js';

describe('capability detection', () => {
  it('detects wakeLock capability when present', () => {
    const originalNavigator = globalThis.navigator;
    try {
      Object.defineProperty(globalThis, 'navigator', {
        value: { wakeLock: { request: vi.fn() } },
        configurable: true,
      });
      expect(isWakeLockSupported()).toBe(true);

      Object.defineProperty(globalThis, 'navigator', {
        value: {},
        configurable: true,
      });
      expect(isWakeLockSupported()).toBe(false);
    } finally {
      Object.defineProperty(globalThis, 'navigator', {
        value: originalNavigator,
        configurable: true,
      });
    }
  });

  it('detects web share capability when present', () => {
    const originalNavigator = globalThis.navigator;
    try {
      Object.defineProperty(globalThis, 'navigator', {
        value: { share: vi.fn() },
        configurable: true,
      });
      expect(isWebShareSupported()).toBe(true);

      Object.defineProperty(globalThis, 'navigator', {
        value: { share: 'not-a-func' },
        configurable: true,
      });
      expect(isWebShareSupported()).toBe(false);

      Object.defineProperty(globalThis, 'navigator', {
        value: {},
        configurable: true,
      });
      expect(isWebShareSupported()).toBe(false);
    } finally {
      Object.defineProperty(globalThis, 'navigator', {
        value: originalNavigator,
        configurable: true,
      });
    }
  });

  it('detects storage quota capability when present', () => {
    const originalNavigator = globalThis.navigator;
    try {
      Object.defineProperty(globalThis, 'navigator', {
        value: { storage: { estimate: vi.fn() } },
        configurable: true,
      });
      expect(isStorageQuotaSupported()).toBe(true);

      Object.defineProperty(globalThis, 'navigator', {
        value: { storage: {} },
        configurable: true,
      });
      expect(isStorageQuotaSupported()).toBe(false);

      Object.defineProperty(globalThis, 'navigator', {
        value: {},
        configurable: true,
      });
      expect(isStorageQuotaSupported()).toBe(false);
    } finally {
      Object.defineProperty(globalThis, 'navigator', {
        value: originalNavigator,
        configurable: true,
      });
    }
  });

  it('probes storage capabilities and returns structured matrix', async () => {
    const caps = await probeStorageCapabilities();
    expect(caps).toHaveProperty('persistentTrust');
    expect(caps).toHaveProperty('opfs');
    expect(caps).toHaveProperty('syncAccessHandle');
    expect(caps).toHaveProperty('quotaEstimate');
    expect(caps).toHaveProperty('directFileSystem');
    expect(caps).toHaveProperty('canStreamToDisk');
  });

  it('probes direct file system support cleanly', () => {
    const supported = isDirectFileSystemSupported();
    expect(typeof supported).toBe('boolean');
  });

  it('returns false cleanly when WebCrypto subtle is unavailable for persistent trust', async () => {
    const originalCrypto = globalThis.crypto;
    try {
      Object.defineProperty(globalThis, 'crypto', {
        value: {},
        configurable: true,
      });
      const supported = await isPersistentTrustSupported();
      expect(supported).toBe(false);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        value: originalCrypto,
        configurable: true,
      });
    }
  });
});
