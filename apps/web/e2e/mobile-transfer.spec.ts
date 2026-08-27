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

test('mobile viewport send → receive round-trips file and renders QR prominently', async ({
  context,
}) => {
  const sender = await context.newPage();
  await sender.goto('/');
  await sender.getByRole('button', { name: 'Send a file' }).click();

  const codeCard = sender.locator('.code-card');
  await expect(codeCard).toBeVisible({ timeout: 15_000 });
  const code = (await codeCard.locator('.code').textContent())?.trim() ?? '';
  expect(code).toMatch(/^\d+-[a-z]+-[a-z]+$/);

  // QR code canvas is rendered and visible in mobile viewport
  const qrCanvas = sender.locator('.qr canvas');
  await expect(qrCanvas).toBeVisible({ timeout: 10_000 });

  // Receiver navigates with auto-populated query parameter
  const receiver = await context.newPage();
  await receiver.goto(`/?code=${encodeURIComponent(code)}`);

  const codeInput = receiver.locator('#code');
  await expect(codeInput).toHaveValue(code);
  await receiver.getByRole('button', { name: 'Receive' }).click();

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
