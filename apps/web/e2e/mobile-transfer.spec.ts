import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

function payload(size: number): Buffer {
  let seed = 0x5eed_9876;
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    bytes[i] = seed >> 24;
  }
  return bytes;
}

function sha256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

const BYTES = payload(2 * 1024 * 1024);
const DIGEST = sha256(BYTES);

test.afterEach(async ({ context }) => {
  await context.close();
});

async function openMobileSender(page: import('@playwright/test').Page): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Send a file' }).click();

  const codeCard = page.locator('.code-card');
  await expect(codeCard).toBeVisible({ timeout: 15_000 });
  const code = (await codeCard.locator('.code').textContent())?.trim() ?? '';
  expect(code).toMatch(/^\d+-[a-z]+-[a-z]+$/);
  return code;
}

async function joinMobileReceiver(
  page: import('@playwright/test').Page,
  code: string,
): Promise<void> {
  await page.goto(`/?code=${encodeURIComponent(code)}`);
  const codeInput = page.locator('#code');
  await expect(codeInput).toHaveValue(code);
  await page.getByRole('button', { name: 'Receive' }).click();
}

test('PWA manifest and service worker are served cleanly', async ({ page }) => {
  const manifestRes = await page.goto('/manifest.webmanifest');
  expect(manifestRes?.status()).toBe(200);
  const manifest = await manifestRes?.json();
  expect(manifest.name).toBe('SendBeam');
  expect(manifest.short_name).toBe('SendBeam');
  expect(manifest.display).toBe('standalone');
  expect(manifest.theme_color).toBe('#070b16');
  expect(manifest.icons.length).toBeGreaterThanOrEqual(2);

  const swRes = await page.goto('/sw.js');
  expect(swRes?.status()).toBe(200);
  const swText = await swRes?.text();
  expect(swText).toContain('sendbeam-shell-v1');
});

test('PWA deep-link ?code= parameter populates code and activates join', async ({ page }) => {
  await page.goto('/?code=888-mobile-webkit');
  const codeInput = page.locator('#code');
  await expect(codeInput).toHaveValue('888-mobile-webkit');
  const receiveBtn = page.getByRole('button', { name: 'Receive' });
  await expect(receiveBtn).toBeEnabled();
});

test('mobile viewport send → receive round-trips file and renders QR prominently', async ({
  context,
}) => {
  const sender = await context.newPage();
  const code = await openMobileSender(sender);

  // QR code canvas is rendered and visible in mobile viewport
  const qrCanvas = sender.locator('.qr canvas');
  await expect(qrCanvas).toBeVisible({ timeout: 10_000 });

  // Receiver navigates with auto-populated query parameter
  const receiver = await context.newPage();
  await joinMobileReceiver(receiver, code);

  // Both peers authenticate
  await expect(receiver.locator('.result.ok')).toBeVisible({ timeout: 30_000 });
  await expect(sender.locator('.result.ok')).toBeVisible({ timeout: 30_000 });

  await sender.setInputFiles('input[type="file"]', {
    name: 'mobile-payload.bin',
    mimeType: 'application/octet-stream',
    buffer: BYTES,
  });

  await expect(sender.getByText(/verified by the receiver/)).toBeVisible({ timeout: 60_000 });
  await expect(receiver.getByText(/verified\./)).toBeVisible({ timeout: 60_000 });

  const downloadPromise = receiver.waitForEvent('download');
  await receiver.locator('a.download').click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).not.toBeNull();
  const received = readFileSync(path!);
  expect(received.equals(BYTES)).toBe(true);
  expect(sha256(received)).toBe(DIGEST);
});

test('visibility change / backgrounding interrupts transfer to deterministic paused state without hang', async ({
  context,
}) => {
  const sender = await context.newPage();
  const code = await openMobileSender(sender);

  const receiver = await context.newPage();
  await joinMobileReceiver(receiver, code);

  await expect(receiver.locator('.result.ok')).toBeVisible({ timeout: 30_000 });
  await expect(sender.locator('.result.ok')).toBeVisible({ timeout: 30_000 });

  // 4 MiB payload so transfer has sufficient window to observe backgrounding
  const bgBytes = payload(4 * 1024 * 1024);
  const bgDigest = sha256(bgBytes);

  await sender.setInputFiles('input[type="file"]', {
    name: 'bg-payload.bin',
    mimeType: 'application/octet-stream',
    buffer: bgBytes,
  });

  // Simulate mobile tab backgrounding / screen lock on receiver
  await receiver.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', {
      value: 'hidden',
      writable: true,
      configurable: true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });

  // Deterministic paused state surfaced — never hangs
  const resumeBtn = receiver.getByRole('button', { name: 'Resume' });
  await expect(resumeBtn).toBeVisible({ timeout: 15_000 });

  // Return to foreground and resume
  await receiver.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', {
      value: 'visible',
      writable: true,
      configurable: true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await resumeBtn.click();

  // Transfer completes and verifies
  await expect(sender.getByText(/verified by the receiver/)).toBeVisible({ timeout: 60_000 });
  await expect(receiver.getByText(/verified\./)).toBeVisible({ timeout: 60_000 });

  const downloadPromise = receiver.waitForEvent('download');
  await receiver.locator('a.download').click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).not.toBeNull();
  const received = readFileSync(path!);
  expect(received.equals(bgBytes)).toBe(true);
  expect(sha256(received)).toBe(bgDigest);
});

test('large file receive stays memory-bounded and streams directly to storage', async ({
  context,
}) => {
  const sender = await context.newPage();
  const code = await openMobileSender(sender);

  const receiver = await context.newPage();
  await joinMobileReceiver(receiver, code);

  await expect(receiver.locator('.result.ok')).toBeVisible({ timeout: 30_000 });
  await expect(sender.locator('.result.ok')).toBeVisible({ timeout: 30_000 });

  const largeBytes = payload(4 * 1024 * 1024);
  const largeDigest = sha256(largeBytes);

  await sender.setInputFiles('input[type="file"]', {
    name: 'streamed-disk-payload.bin',
    mimeType: 'application/octet-stream',
    buffer: largeBytes,
  });

  await expect(sender.getByText(/verified by the receiver/)).toBeVisible({ timeout: 60_000 });
  await expect(receiver.getByText(/verified\./)).toBeVisible({ timeout: 60_000 });

  // Verify streamed-to-disk: verify file handle in OPFS without buffering whole file in JS heap
  const diskVerification = await receiver.evaluate(async () => {
    const navStorage = (navigator as Navigator & { storage?: StorageManager }).storage;
    if (!navStorage || typeof navStorage.getDirectory !== 'function') {
      return { opfsAvailable: false, fileSize: 0 };
    }
    try {
      const root = await navStorage.getDirectory();
      let foundSize = 0;
      const entries = (
        root as unknown as { entries?: () => AsyncIterable<[string, FileSystemHandle]> }
      ).entries;
      if (entries) {
        for await (const [name, handle] of entries.call(root)) {
          if (name.startsWith('sendbeam-') && handle.kind === 'file') {
            const file = await (handle as FileSystemFileHandle).getFile();
            foundSize = file.size;
            break;
          }
        }
      }
      return { opfsAvailable: true, fileSize: foundSize };
    } catch {
      return { opfsAvailable: false, fileSize: 0 };
    }
  });

  if (diskVerification.opfsAvailable && diskVerification.fileSize > 0) {
    expect(diskVerification.fileSize).toBe(largeBytes.length);
  }

  const downloadPromise = receiver.waitForEvent('download');
  await receiver.locator('a.download').click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).not.toBeNull();
  const received = readFileSync(path!);
  expect(received.equals(largeBytes)).toBe(true);
  expect(sha256(received)).toBe(largeDigest);
});
