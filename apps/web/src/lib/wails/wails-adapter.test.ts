import { describe, expect, it, vi } from 'vitest';
import {
  createDeviceServiceAdapter,
  createTransferServiceAdapter,
  createUpdateServiceAdapter,
  createEngineServiceAdapter,
  getWailsBridge,
  isWailsV3Available,
  WAILS_SERVICES,
  WAILS_EVENTS,
} from './wails-adapter.js';

describe('Wails v3 typed adapter layer', () => {
  it('exposes correct service FQNs and event names', () => {
    expect(WAILS_SERVICES.Device).toBe('github.com/sendbeam/desktop/internal/engine.DeviceService');
    expect(WAILS_SERVICES.Transfer).toBe(
      'github.com/sendbeam/desktop/internal/engine.TransferService',
    );
    expect(WAILS_SERVICES.Update).toBe('github.com/sendbeam/desktop/internal/engine.UpdateService');
    expect(WAILS_SERVICES.Service).toBe('github.com/sendbeam/desktop/internal/engine.Service');

    expect(WAILS_EVENTS.Transfer).toBe('sendbeam:transfer');
    expect(WAILS_EVENTS.Consent).toBe('sendbeam:consent');
    expect(WAILS_EVENTS.Devices).toBe('sendbeam:devices');
    expect(WAILS_EVENTS.Update).toBe('sendbeam:update');
  });

  it('detects Wails v3 availability correctly', () => {
    const originalWindow = globalThis.window;
    try {
      (globalThis as unknown as { window: unknown }).window = {};
      expect(isWailsV3Available()).toBe(false);

      (globalThis as unknown as { window: unknown }).window = {
        wails: {
          Call: { ByName: vi.fn() },
        },
      };
      expect(isWailsV3Available()).toBe(true);
      expect(getWailsBridge()).not.toBeNull();
    } finally {
      globalThis.window = originalWindow;
    }
  });

  it('device service adapter formats calls correctly', async () => {
    const mockCall = vi.fn().mockResolvedValue([]);
    const adapter = createDeviceServiceAdapter(mockCall);

    await adapter.listTrustedDevices();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Device}.ListTrustedDevices`);

    mockCall.mockResolvedValue({ code: '7-words', qr: 'data:image/png;base64,123' });
    const offer = await adapter.startPairingOffer('wss://hub', 'Desktop', true, '/tmp/down');
    expect(mockCall).toHaveBeenCalledWith(
      `${WAILS_SERVICES.Device}.StartPairingOffer`,
      'wss://hub',
      'Desktop',
      true,
      '/tmp/down',
    );
    expect(offer.code).toBe('7-words');

    await adapter.cancelPairingOffer();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Device}.CancelPairingOffer`);

    await adapter.pairDevice('wss://hub', 'code1', 'label1', false, '');
    expect(mockCall).toHaveBeenCalledWith(
      `${WAILS_SERVICES.Device}.PairDevice`,
      'wss://hub',
      'code1',
      'label1',
      false,
      '',
    );

    await adapter.renameDevice('dev-1', 'New Name');
    expect(mockCall).toHaveBeenCalledWith(
      `${WAILS_SERVICES.Device}.RenameDevice`,
      'dev-1',
      'New Name',
    );

    await adapter.updateDevicePolicy('dev-1', { autoAccept: true, autoAcceptDestDir: '/dl' });
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Device}.UpdateDevicePolicy`, 'dev-1', {
      autoAccept: true,
      autoAcceptDestDir: '/dl',
    });

    await adapter.unpairDevice('dev-1', true);
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Device}.UnpairDevice`, 'dev-1', true);
  });

  it('transfer service adapter formats targeted and broadcast calls correctly', async () => {
    const mockCall = vi.fn().mockResolvedValue({ id: 'tx-1', role: 'send' });
    const adapter = createTransferServiceAdapter(mockCall);

    await adapter.send(['/tmp/file.txt']);
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Transfer}.Send`, ['/tmp/file.txt'], '');

    await adapter.sendToDevice(['/tmp/file.txt'], 'dev-42');
    expect(mockCall).toHaveBeenCalledWith(
      `${WAILS_SERVICES.Transfer}.SendToDevice`,
      ['/tmp/file.txt'],
      'dev-42',
      '',
    );

    mockCall.mockResolvedValue([{ target_id: 'dev-1', status: 'ok', duration_ms: 100 }]);
    const bResult = await adapter.broadcastSend(['/tmp/file.txt'], ['dev-1', 'dev-2']);
    expect(mockCall).toHaveBeenCalledWith(
      `${WAILS_SERVICES.Transfer}.BroadcastSend`,
      ['/tmp/file.txt'],
      ['dev-1', 'dev-2'],
      '',
    );
    expect(bResult[0]?.status).toBe('ok');

    await adapter.respondConsent('tx-99', { accepted: true, destDir: '/downloads' });
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Transfer}.RespondConsent`, 'tx-99', {
      accepted: true,
      destDir: '/downloads',
    });
  });

  it('update and engine service adapters format calls correctly', async () => {
    const mockCall = vi.fn().mockResolvedValue({});
    const updateAdapter = createUpdateServiceAdapter(mockCall);

    await updateAdapter.getStatus();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Update}.GetStatus`);

    await updateAdapter.checkUpdate('beta');
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Update}.CheckUpdate`, 'beta');

    await updateAdapter.setChannel('stable');
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Update}.SetChannel`, 'stable');

    await updateAdapter.applyUpdate();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Update}.ApplyUpdate`);

    const engineAdapter = createEngineServiceAdapter(mockCall);
    await engineAdapter.info();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Service}.Info`);

    await engineAdapter.caps();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Service}.Caps`);

    await engineAdapter.selfCheck();
    expect(mockCall).toHaveBeenCalledWith(`${WAILS_SERVICES.Service}.SelfCheck`);
  });
});
