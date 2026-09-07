/** @vitest-environment jsdom */

import { mount, tick, unmount } from 'svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import IncomingTransferModal from './IncomingTransferModal.svelte';
import type { IncomingTransferRequest } from './types.js';

describe('IncomingTransferModal Component', () => {
  let target: HTMLDivElement;
  let component: ReturnType<typeof mount> | null = null;

  beforeEach(() => {
    target = document.createElement('div');
    document.body.appendChild(target);
  });

  afterEach(() => {
    if (component) {
      unmount(component);
      component = null;
    }
    target.remove();
  });

  it('renders nothing when request is null', () => {
    component = mount(IncomingTransferModal, {
      target,
      props: {
        request: null,
        onAccept: vi.fn(),
        onDecline: vi.fn(),
      },
    });

    expect(target.querySelector('.modal-backdrop')).toBeNull();
  });

  it('renders request details and triggers onAccept', async () => {
    const onAccept = vi.fn();
    const onDecline = vi.fn();

    const request: IncomingTransferRequest = {
      transferId: 'req-123',
      senderDeviceId: 'sb-dev-phone123',
      senderLabel: 'Pixel 8 Pro',
      senderFingerprint: 'A1B2 C3D4',
      fileCount: 2,
      totalBytes: 2048,
      files: [
        { name: 'photo1.jpg', size: 1024 },
        { name: 'photo2.jpg', size: 1024 },
      ],
    };

    component = mount(IncomingTransferModal, {
      target,
      props: {
        request,
        onAccept,
        onDecline,
      },
    });

    expect(target.querySelector('.modal-backdrop')).not.toBeNull();
    expect(target.textContent).toContain('Pixel 8 Pro');
    expect(target.textContent).toContain('A1B2 C3D4');
    expect(target.textContent).toContain('2 file(s)');
    expect(target.textContent).toContain('photo1.jpg');
    expect(target.textContent).toContain('photo2.jpg');

    const acceptBtn = target.querySelector('.btn-accept') as HTMLButtonElement;
    expect(acceptBtn).not.toBeNull();
    acceptBtn.click();
    await tick();

    expect(onAccept).toHaveBeenCalledOnce();
    expect(onDecline).not.toHaveBeenCalled();
  });

  it('triggers onDecline when decline button clicked', async () => {
    const onAccept = vi.fn();
    const onDecline = vi.fn();

    const request: IncomingTransferRequest = {
      transferId: 'req-456',
      senderDeviceId: 'sb-dev-unknown',
      senderLabel: 'Unknown Device',
      senderFingerprint: '9988 7766',
      fileCount: 1,
      totalBytes: 500,
      files: [{ name: 'secret.zip', size: 500 }],
    };

    component = mount(IncomingTransferModal, {
      target,
      props: {
        request,
        onAccept,
        onDecline,
      },
    });

    const declineBtn = target.querySelector('.btn-decline') as HTMLButtonElement;
    expect(declineBtn).not.toBeNull();
    declineBtn.click();
    await tick();

    expect(onDecline).toHaveBeenCalledOnce();
    expect(onAccept).not.toHaveBeenCalled();
  });

  it('truncates file list when more than 5 files are sent', () => {
    const files = Array.from({ length: 8 }, (_, i) => ({
      name: `file_${i + 1}.txt`,
      size: 100,
    }));

    const request: IncomingTransferRequest = {
      transferId: 'req-multi',
      senderDeviceId: 'sb-dev-sender',
      senderLabel: 'Work Desktop',
      senderFingerprint: '1122 3344',
      fileCount: files.length,
      totalBytes: 800,
      files,
    };

    component = mount(IncomingTransferModal, {
      target,
      props: {
        request,
        onAccept: vi.fn(),
        onDecline: vi.fn(),
      },
    });

    expect(target.querySelectorAll('.file-item')).toHaveLength(5);
    expect(target.textContent).toContain('+ 3 more file(s)');
  });
});
