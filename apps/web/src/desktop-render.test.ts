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

  it('renders trusted devices list with literal text and status badges without injecting HTML', async () => {
    const maliciousLabel = '<script id="xss-dev-label">alert(1)</script>Workstation';
    const maliciousFp = '<b id="xss-dev-fp">deadbeefcafe1234</b>';

    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([
            {
              deviceId: 'dev-lan-1',
              localLabel: maliciousLabel,
              fingerprint: maliciousFp,
              status: 'lan_direct',
              revoked: false,
              policy: { autoAccept: true, autoAcceptDestDir: '/tmp/incoming' },
              lastSeen: 1710000000,
            },
            {
              deviceId: 'dev-online-2',
              localLabel: 'Phone',
              fingerprint: '1122334455667788',
              status: 'online',
              revoked: false,
              policy: { autoAccept: false },
              lastSeen: 0,
            },
            {
              deviceId: 'dev-revoked-3',
              localLabel: 'Old Laptop',
              fingerprint: '9988776655443322',
              status: 'offline',
              revoked: true,
              policy: { autoAccept: false },
              lastSeen: 1709000000,
            },
          ]);
        }
        return Promise.resolve({});
      },
    });

    const tab = document.getElementById('tab-devices') as HTMLButtonElement;
    tab.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(document.querySelector('#xss-dev-label')).toBeNull();
    expect(document.querySelector('#xss-dev-fp')).toBeNull();

    const tbody = document.getElementById('devices-tbody');
    expect(tbody).not.toBeNull();
    const rows = tbody?.querySelectorAll('tr');
    expect(rows?.length).toBe(3);

    // Verify row 1 (lan_direct)
    const row1 = rows?.[0];
    expect(row1?.textContent).toContain(maliciousLabel);
    expect(row1?.textContent).toContain(maliciousFp);
    expect(row1?.querySelector('.badge-lan')?.textContent).toBe('LAN Direct');
    expect(row1?.textContent).toContain('Yes (/tmp/incoming)');

    // Verify row 2 (online)
    const row2 = rows?.[1];
    expect(row2?.querySelector('.badge-online')?.textContent).toBe('Online');
    expect(row2?.textContent).toContain('No');

    // Verify row 3 (revoked takes precedence)
    const row3 = rows?.[2];
    expect(row3?.querySelector('.badge-revoked')?.textContent).toBe('Revoked');

    // Action buttons must exist
    expect(row1?.querySelector('button[data-action="policy"]')).not.toBeNull();
    expect(row1?.querySelector('button[data-action="rename"]')).not.toBeNull();
    expect(row1?.querySelector('button[data-action="unpair"]')).not.toBeNull();
  });

  it('updates send recipient dropdown with trusted devices and broadcast option', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([
            {
              deviceId: 'dev-100',
              localLabel: '<script id="xss-opt">alert(1)</script>Tablet',
              fingerprint: 'aabbccddeeff0011',
              status: 'online',
              revoked: false,
            },
            {
              deviceId: 'dev-200',
              localLabel: 'Desktop PC',
              fingerprint: '3344556677889900',
              status: 'lan_direct',
              revoked: false,
            },
            {
              deviceId: 'dev-revoked',
              localLabel: 'Old Phone',
              fingerprint: '1100ffeeddccbbaa',
              status: 'offline',
              revoked: true,
            },
          ]);
        }
        return Promise.resolve({});
      },
    });

    const tab = document.getElementById('tab-devices') as HTMLButtonElement;
    tab.click();
    await new Promise((r) => setTimeout(r, 50));

    const recipientSelect = document.getElementById('send-recipient') as HTMLSelectElement;
    expect(recipientSelect).not.toBeNull();
    expect(document.querySelector('#xss-opt')).toBeNull();

    const options = Array.from(recipientSelect.options);
    expect(options.some((opt) => opt.value === 'code')).toBe(true);
    expect(options.some((opt) => opt.value === 'broadcast:all')).toBe(true);
    const tabletOpt = options.find((opt) => opt.value === 'dev-100');
    expect(tabletOpt).toBeDefined();
    expect(tabletOpt?.textContent).toContain('<script id="xss-opt">alert(1)</script>Tablet');
    // Revoked device should not appear in active recipients
    expect(options.some((opt) => opt.value === 'dev-revoked')).toBe(false);
  });

  it('handles pairing modal offer and join flows securely', async () => {
    let pairingOfferCalled = false;
    let cancelPairingOfferCalled = false;
    let pairDevicePayload: unknown[] | null = null;

    const { document } = setupDesktopDOM({
      onCall: (name, ...args) => {
        if (name.includes('StartPairingOffer')) {
          pairingOfferCalled = true;
          return Promise.resolve({
            code: 'test-pair-code',
            qr: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          });
        }
        if (name.includes('CancelPairingOffer')) {
          cancelPairingOfferCalled = true;
          return Promise.resolve({});
        }
        if (name.includes('PairDevice')) {
          pairDevicePayload = args;
          return Promise.resolve({});
        }
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([]);
        }
        return Promise.resolve({});
      },
    });

    const pairBtn = document.getElementById('open-pair-btn') as HTMLButtonElement;
    pairBtn.click();
    await new Promise((r) => setTimeout(r, 50));

    const modalPair = document.getElementById('modal-pair');
    expect(modalPair?.classList.contains('hidden')).toBe(false);
    expect(pairingOfferCalled).toBe(true);
    expect(document.getElementById('pair-offer-code')?.textContent).toBe('test-pair-code');
    const qrImg = document.getElementById('pair-offer-qr') as HTMLImageElement;
    expect(qrImg.src).toContain('data:image/png;base64');

    // Switch to Join tab
    const joinTab = document.getElementById('pair-tab-join') as HTMLButtonElement;
    joinTab.click();
    expect(document.getElementById('pair-join-view')?.classList.contains('hidden')).toBe(false);

    // Fill form and submit
    const codeInput = document.getElementById('pair-join-code') as HTMLInputElement;
    const labelInput = document.getElementById('pair-join-label') as HTMLInputElement;
    const autoAccept = document.getElementById('pair-join-auto-accept') as HTMLInputElement;
    const destDir = document.getElementById('pair-join-dest-dir') as HTMLInputElement;

    codeInput.value = 'partner-code-99';
    labelInput.value = 'My Partner';
    autoAccept.checked = true;
    autoAccept.dispatchEvent(
      new (document.defaultView as unknown as { Event: typeof Event }).Event('change'),
    );
    destDir.value = '/tmp/partner-downloads';

    const joinSubmit = document.getElementById('pair-join-submit') as HTMLButtonElement;
    joinSubmit.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(pairDevicePayload).toEqual([
      '',
      'partner-code-99',
      'My Partner',
      true,
      '/tmp/partner-downloads',
    ]);

    // Closing modal invokes cancel
    const closeBtn = document.getElementById('pair-modal-close') as HTMLButtonElement;
    closeBtn.click();
    expect(cancelPairingOfferCalled).toBe(true);
  });

  it('handles policy modal editing and saving', async () => {
    let updatedPolicy: unknown = null;

    const { document } = setupDesktopDOM({
      onCall: (name, ...args) => {
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([
            {
              deviceId: 'dev-policy-test',
              localLabel: 'Policy Node',
              fingerprint: 'deadbeef1122',
              status: 'online',
              revoked: false,
              policy: { autoAccept: false, autoAcceptDestDir: '' },
            },
          ]);
        }
        if (name.includes('UpdateDevicePolicy')) {
          updatedPolicy = args;
          return Promise.resolve({});
        }
        return Promise.resolve({});
      },
    });

    const tab = document.getElementById('tab-devices') as HTMLButtonElement;
    tab.click();
    await new Promise((r) => setTimeout(r, 50));

    const policyBtn = document.querySelector('button[data-action="policy"]') as HTMLButtonElement;
    policyBtn.click();

    const modalPolicy = document.getElementById('modal-policy');
    expect(modalPolicy?.classList.contains('hidden')).toBe(false);

    const autoAccept = document.getElementById('policy-auto-accept') as HTMLInputElement;
    const destDir = document.getElementById('policy-dest-dir') as HTMLInputElement;
    autoAccept.checked = true;
    destDir.value = '/home/user/vault';

    const saveBtn = document.getElementById('policy-save-btn') as HTMLButtonElement;
    saveBtn.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(updatedPolicy).toEqual([
      'dev-policy-test',
      { autoAccept: true, autoAcceptDestDir: '/home/user/vault' },
    ]);
  });

  it('handles rename modal editing and saving', async () => {
    let renameArgs: unknown = null;

    const { document } = setupDesktopDOM({
      onCall: (name, ...args) => {
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([
            {
              deviceId: 'dev-rename-test',
              localLabel: 'Old Name',
              fingerprint: 'deadbeef1122',
              status: 'online',
              revoked: false,
            },
          ]);
        }
        if (name.includes('RenameDevice')) {
          renameArgs = args;
          return Promise.resolve({});
        }
        return Promise.resolve({});
      },
    });

    const tab = document.getElementById('tab-devices') as HTMLButtonElement;
    tab.click();
    await new Promise((r) => setTimeout(r, 50));

    const renameBtn = document.querySelector('button[data-action="rename"]') as HTMLButtonElement;
    renameBtn.click();

    const modalRename = document.getElementById('modal-rename');
    expect(modalRename?.classList.contains('hidden')).toBe(false);

    const input = document.getElementById('rename-label-input') as HTMLInputElement;
    expect(input.value).toBe('Old Name');
    input.value = 'New Friendly Name';

    const saveBtn = document.getElementById('rename-save-btn') as HTMLButtonElement;
    saveBtn.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(renameArgs).toEqual(['dev-rename-test', 'New Friendly Name']);
  });

  it('handles unpair modal with purge option', async () => {
    let unpairArgs: unknown = null;

    const { document } = setupDesktopDOM({
      onCall: (name, ...args) => {
        if (name.includes('ListTrustedDevices')) {
          return Promise.resolve([
            {
              deviceId: 'dev-unpair-test',
              localLabel: '<b id="xss-unpair">Node</b>',
              fingerprint: 'deadbeef1122',
              status: 'online',
              revoked: false,
            },
          ]);
        }
        if (name.includes('UnpairDevice')) {
          unpairArgs = args;
          return Promise.resolve({});
        }
        return Promise.resolve({});
      },
    });

    const tab = document.getElementById('tab-devices') as HTMLButtonElement;
    tab.click();
    await new Promise((r) => setTimeout(r, 50));

    const unpairBtn = document.querySelector('button[data-action="unpair"]') as HTMLButtonElement;
    unpairBtn.click();

    expect(document.querySelector('#xss-unpair')).toBeNull();
    const modalUnpair = document.getElementById('modal-unpair');
    expect(modalUnpair?.classList.contains('hidden')).toBe(false);

    // Select purge radio
    const purgeRadio = document.querySelector(
      'input[name="unpair-mode"][value="purge"]',
    ) as HTMLInputElement;
    purgeRadio.checked = true;

    const confirmBtn = document.getElementById('unpair-confirm-btn') as HTMLButtonElement;
    confirmBtn.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(unpairArgs).toEqual(['dev-unpair-test', true]);
  });

  it('handles incoming consent modal prompt and responses safely', async () => {
    let consentResponse: unknown = null;

    const { document, emit } = setupDesktopDOM({
      onCall: (name, ...args) => {
        if (name.includes('RespondConsent')) {
          consentResponse = args;
          return Promise.resolve({});
        }
        return Promise.resolve({});
      },
    });

    const maliciousPeer = '<script id="xss-peer-name">alert(1)</script>Bob';
    const maliciousFp = '<i id="xss-peer-fp">1234abcd</i>';
    const maliciousFile = '<span id="xss-peer-file">report.pdf</span>';

    emit('sendbeam:consent', {
      transferId: 'tx-consent-101',
      peerDeviceId: 'peer-device-id',
      peerName: maliciousPeer,
      fingerprint: maliciousFp,
      fileName: maliciousFile,
      totalSize: 4194304,
      destDir: '/tmp/safe-inbox',
    });

    const modalConsent = document.getElementById('modal-consent');
    expect(modalConsent?.classList.contains('hidden')).toBe(false);

    expect(document.querySelector('#xss-peer-name')).toBeNull();
    expect(document.querySelector('#xss-peer-fp')).toBeNull();
    expect(document.querySelector('#xss-peer-file')).toBeNull();

    expect(document.getElementById('consent-device-name')?.textContent).toBe(maliciousPeer);
    expect(document.getElementById('consent-fingerprint')?.textContent).toBe(maliciousFp);
    expect(document.getElementById('consent-files-summary')?.textContent).toContain(maliciousFile);

    const acceptBtn = document.getElementById('consent-accept-btn') as HTMLButtonElement;
    acceptBtn.click();
    await new Promise((r) => setTimeout(r, 50));

    expect(consentResponse).toEqual([
      'tx-consent-101',
      {
        accepted: true,
        destDir: '/tmp/safe-inbox',
      },
    ]);
  });
});
