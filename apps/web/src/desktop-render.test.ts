import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
// @ts-expect-error jsdom lacks bundled type definitions
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';

const htmlPath = resolve(__dirname, '../../desktop/frontend/dist/index.html');
const htmlContent = readFileSync(htmlPath, 'utf8');

function setupDesktopDOM(options?: {
  onCall?: (name: string, ...args: unknown[]) => Promise<unknown>;
}) {
  const events: Record<string, ((ev: unknown) => void)[]> = {};
  const dom = new JSDOM(htmlContent, {
    url: 'http://localhost',
    runScripts: 'dangerously',
    beforeParse(win: Record<string, unknown>) {
      // Mock Wails v3 runtime
      win.wails = {
        Events: {
          On: (name: string, cb: (ev: unknown) => void) => {
            if (!events[name]) events[name] = [];
            events[name].push(cb);
          },
        },
        Call: {
          ByName: (name: string, ...args: unknown[]) => {
            if (options?.onCall) {
              return options.onCall(name, ...args);
            }
            return Promise.resolve({});
          },
        },
      };
    },
  });

  const emit = (name: string, payload: unknown) => {
    const list = events[name] || [];
    for (const cb of list) {
      cb(payload);
    }
  };

  return { dom, window: dom.window, document: dom.window.document, emit };
}

describe('Desktop frontend literal-text rendering', () => {
  it('contains zero usage of innerHTML in source', () => {
    expect(htmlContent).not.toContain('innerHTML');
    expect(htmlContent).not.toContain('outerHTML');
    expect(htmlContent).not.toContain('document.write');
    expect(htmlContent).not.toContain('insertAdjacentHTML');
  });

  it('renders transfer error as literal text without injecting HTML elements', () => {
    const { document, emit } = setupDesktopDOM();

    // Adopt transfer ID via drop
    emit('sendbeam:transfer', {
      kind: 'drop',
      id: 'tx-err-1',
      files: ['/tmp/file.txt'],
    });

    // Send error event containing malicious HTML tags and event handlers
    const payload = '<img src="x" onerror="window.__xss1=1"><b id="xss-err-tag">error</b>';
    emit('sendbeam:transfer', {
      kind: 'error',
      id: 'tx-err-1',
      error: payload,
    });

    const sendStatus = document.getElementById('send-status');
    expect(sendStatus).not.toBeNull();
    // Element must NOT have parsed child elements
    expect(sendStatus?.querySelector('img')).toBeNull();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('#xss-err-tag')).toBeNull();
    // Text must be literal
    expect(sendStatus?.textContent).toContain(payload);
  });

  it('renders done transfer outPath as literal text without injecting HTML elements', () => {
    const { document, emit } = setupDesktopDOM();

    emit('sendbeam:transfer', {
      kind: 'drop',
      id: 'tx-done-1',
      files: ['/tmp/file.txt'],
    });

    const maliciousPath =
      '/home/user/<svg onload="window.__xss2=1"><div id="xss-path-tag">dir</div>';
    emit('sendbeam:transfer', {
      kind: 'done',
      id: 'tx-done-1',
      outPath: maliciousPath,
    });

    const sendStatus = document.getElementById('send-status');
    expect(sendStatus).not.toBeNull();
    expect(document.querySelector('svg')).toBeNull();
    expect(document.querySelector('#xss-path-tag')).toBeNull();
    expect(sendStatus?.textContent).toContain(maliciousPath);
  });

  it('renders transfer chips as literal text without injecting HTML elements', () => {
    const { document, emit } = setupDesktopDOM();

    emit('sendbeam:transfer', {
      kind: 'drop',
      id: 'tx-chip-1',
      files: ['/tmp/file.txt'],
    });

    emit('sendbeam:transfer', {
      kind: 'progress',
      id: 'tx-chip-1',
      phase: '<b id="xss_chip_tag">connecting</b>',
      transport: '<i id="xss_transport_tag">relay</i>',
      fingerprint: '<span id="xss_fp_tag">fp123</span>',
      state: '<u id="xss_state_tag">transferring</u>',
    });

    expect(document.querySelector('#xss_chip_tag')).toBeNull();
    expect(document.querySelector('#xss_transport_tag')).toBeNull();
    expect(document.querySelector('#xss_fp_tag')).toBeNull();
    expect(document.querySelector('#xss_state_tag')).toBeNull();

    const chips = document.getElementById('send-chips');
    expect(chips?.textContent).toContain('<b id="xss_chip_tag">connecting</b>');
    expect(chips?.textContent).toContain('<i id="xss_transport_tag">relay</i>');
  });

  it('renders interrupted transfers list as literal text without injecting HTML elements', async () => {
    const maliciousId = '<script id="xss-script">alert(1)</script>';
    const maliciousRole = '<b id="xss-role">joiner</b>';
    const maliciousStatus = '<img id="xss-status-img" src="x" onerror="1">';

    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListInterrupted')) {
          return Promise.resolve([
            {
              role: maliciousRole,
              transferId: maliciousId,
              files: 2,
              committedBytes: 1024,
              totalBytes: 2048,
              status: maliciousStatus,
            },
          ]);
        }
        return Promise.resolve({});
      },
    });

    // Switch to interrupted tab
    const tab = document.getElementById('tab-interrupted') as HTMLButtonElement;
    tab.click();

    // Allow promise microtasks to run
    await new Promise((r) => setTimeout(r, 50));

    const tbody = document.getElementById('durable-tbody');
    expect(tbody).not.toBeNull();
    expect(document.querySelector('#xss-script')).toBeNull();
    expect(document.querySelector('#xss-role')).toBeNull();
    expect(document.querySelector('#xss-status-img')).toBeNull();

    // Verify dataset.id preserves exact literal transfer ID safely
    const inspectBtn = tbody?.querySelector('button[data-action="inspect"]') as HTMLButtonElement;
    expect(inspectBtn).not.toBeNull();
    expect(inspectBtn.dataset.id).toBe(maliciousId);
  });

  it('renders settings status and errors as literal text', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('SaveConfig')) {
          return Promise.reject(new Error('<b id="xss-settings-err">Save failed</b>'));
        }
        return Promise.resolve({});
      },
    });

    const saveBtn = document.getElementById('save-settings') as HTMLButtonElement;
    saveBtn.click();

    await new Promise((r) => setTimeout(r, 50));

    expect(document.querySelector('#xss-settings-err')).toBeNull();
    const settingsStatus = document.getElementById('settings-status');
    expect(settingsStatus?.textContent).toContain('<b id="xss-settings-err">Save failed</b>');
  });

  it('renders update notifications as literal text', () => {
    const { document, emit } = setupDesktopDOM();

    emit('sendbeam:update', {
      state: 'available',
      latestVersion: '2.0.0<img src="x" onerror="1">',
      releaseNotes: 'Security fixes <script id="xss-notes">alert(1)</script>',
    });

    const statusLabel = document.getElementById('update-status-label');
    expect(statusLabel?.querySelector('img')).toBeNull();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('script#xss-notes')).toBeNull();
    expect(statusLabel?.textContent).toContain('2.0.0<img src="x" onerror="1">');

    const bannerText = document.getElementById('update-banner-text');
    expect(bannerText?.querySelector('img')).toBeNull();
    expect(bannerText?.textContent).toContain('2.0.0<img src="x" onerror="1">');
  });

  it('rejects unsafe protocol schemes on invite QR image', () => {
    const { document, emit } = setupDesktopDOM();

    emit('sendbeam:transfer', {
      kind: 'drop',
      id: 'tx-qr-1',
      files: ['/tmp/file.txt'],
    });

    // Attempt javascript: scheme in qr
    emit('sendbeam:transfer', {
      kind: 'invite',
      id: 'tx-qr-1',
      code: '7-alpha-bravo',
      qr: 'javascript:alert(1)',
    });

    const qrImg = document.getElementById('invite-qr') as HTMLImageElement;
    expect(qrImg.src).not.toContain('javascript');

    // Valid data URI should be accepted
    const validDataUrl =
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    emit('sendbeam:transfer', {
      kind: 'invite',
      id: 'tx-qr-1',
      code: '7-alpha-bravo',
      qr: validDataUrl,
    });
    expect(qrImg.src).toBe(validDataUrl);
  });
});
