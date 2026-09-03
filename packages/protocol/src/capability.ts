export interface StorageCapabilities {
  persistentTrust: boolean;
  opfs: boolean;
  syncAccessHandle: boolean;
  quotaEstimate: boolean;
  directFileSystem: boolean;
  canStreamToDisk: boolean;
}

/** Reports whether the Screen Wake Lock API is available in this environment. */
export function isWakeLockSupported(): boolean {
  return typeof navigator !== 'undefined' && 'wakeLock' in navigator;
}

/** Reports whether the Web Share API is available in this environment. */
export function isWebShareSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'share' in navigator &&
    typeof (navigator as Navigator & { share?: unknown }).share === 'function'
  );
}

/** Reports whether navigator.storage.estimate is available in this environment. */
export function isStorageQuotaSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'storage' in navigator &&
    typeof (navigator as Navigator & { storage?: StorageManager }).storage?.estimate === 'function'
  );
}

/** Reports whether the File System Access API (showSaveFilePicker) is available. */
export function isDirectFileSystemSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    'showSaveFilePicker' in window &&
    typeof (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker === 'function'
  );
}

/**
 * Browser capability detection and persistent trust safety gating.
 *
 * Implements strict capability probing for persistent device trust. Probes for:
 * - Functional WebCrypto subtle API (ed25519 or key derivation / HMAC)
 * - Functional IndexedDB storage
 *
 * Returns false cleanly in insecure or restricted environments (e.g. non-HTTPS,
 * disabled storage, private browsing without IDB). Never fakes persistence via
 * unsafe plaintext localStorage or insecure cookies.
 */
export async function isPersistentTrustSupported(customIdb?: unknown): Promise<boolean> {
  // 1. Check WebCrypto subtle availability
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== 'function' || typeof subtle.importKey !== 'function') {
    return false;
  }

  // 2. Check IndexedDB availability
  const idb = (customIdb ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB) as
    IDBFactory | undefined;
  if (!idb || typeof idb.open !== 'function') {
    return false;
  }

  // 3. Probe IndexedDB read/write in a transient probe database
  const probeDbName = 'sendbeam-probe-storage';
  try {
    const isWorking = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => resolve(false), 1000);
      try {
        const req = idb.open(probeDbName, 1);
        req.onupgradeneeded = () => {
          try {
            req.result.createObjectStore('probe');
          } catch {
            // Ignore upgrade errors handled by onerror
          }
        };
        req.onsuccess = () => {
          clearTimeout(timeout);
          const db = req.result;
          try {
            const tx = db.transaction(['probe'], 'readwrite');
            tx.objectStore('probe').put('probe-val', 'probe-key');
            tx.oncomplete = () => {
              db.close();
              try {
                idb.deleteDatabase(probeDbName);
              } catch {
                // Best effort cleanup
              }
              resolve(true);
            };
            tx.onerror = () => {
              db.close();
              resolve(false);
            };
          } catch {
            db.close();
            resolve(false);
          }
        };
        req.onerror = () => {
          clearTimeout(timeout);
          resolve(false);
        };
      } catch {
        clearTimeout(timeout);
        resolve(false);
      }
    });

    return isWorking;
  } catch {
    return false;
  }
}

/**
 * Probes the complete storage & capability matrix for mobile & desktop browser environments.
 */
export async function probeStorageCapabilities(customIdb?: unknown): Promise<StorageCapabilities> {
  const persistentTrust = await isPersistentTrustSupported(customIdb);

  let opfs = false;
  let syncAccessHandle = false;
  const navStorage =
    typeof navigator !== 'undefined'
      ? (navigator as Navigator & { storage?: StorageManager }).storage
      : undefined;

  if (navStorage && typeof navStorage.getDirectory === 'function') {
    try {
      const root = await navStorage.getDirectory();
      if (root) {
        opfs = true;
        const testFile = await root.getFileHandle('__probe_cap__', { create: true });
        if ('createSyncAccessHandle' in testFile) {
          syncAccessHandle = true;
        }
        await root.removeEntry('__probe_cap__').catch(() => {});
      }
    } catch {
      // OPFS restricted (e.g. non-HTTPS, iOS Safari private mode)
    }
  }

  const quotaEstimate = isStorageQuotaSupported();
  const directFileSystem = isDirectFileSystemSupported();
  const canStreamToDisk = directFileSystem || opfs;

  return {
    persistentTrust,
    opfs,
    syncAccessHandle,
    quotaEstimate,
    directFileSystem,
    canStreamToDisk,
  };
}
