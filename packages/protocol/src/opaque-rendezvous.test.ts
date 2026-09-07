import { describe, expect, it } from 'vitest';
import { hexToBytes } from './bytes.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import { OpaqueRendezvousSession } from './opaque-rendezvous.js';

describe('OpaqueRendezvousSession (sendbeam/3)', () => {
  const seedInit = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111');
  const seedResp = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');
  const kPair = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');
  const validHandle = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  it('rejects invalid handle on start', async () => {
    const idInit = await createDeviceIdentityFromSeed(seedInit);
    const session = new OpaqueRendezvousSession({
      role: 'offerer',
      handle: 'invalid-handle',
      localIdentity: idInit,
      peerDeviceId: 'peer-id',
      peerPublicKey: 'peer-pk',
      kPair,
      pairCredentialRef: 'cred-1',
      send: () => {},
    });

    await session.start();
    expect(session.getPhase()).toBe('failed');
    await expect(session.result).rejects.toThrow('invalid_handle');
  });

  it('completes mutual sendbeam/3 authentication between offerer and joiner', async () => {
    const idInit = await createDeviceIdentityFromSeed(seedInit);
    const idResp = await createDeviceIdentityFromSeed(seedResp);

    const offererOutbox: Record<string, unknown>[] = [];
    const joinerOutbox: Record<string, unknown>[] = [];

    const offererSession = new OpaqueRendezvousSession({
      role: 'offerer',
      handle: validHandle,
      localIdentity: idInit,
      peerDeviceId: idResp.deviceId,
      peerPublicKey: idResp.publicKey,
      kPair,
      pairCredentialRef: 'cred-1',
      send: (msg) => {
        offererOutbox.push(msg as Record<string, unknown>);
      },
    });

    const joinerSession = new OpaqueRendezvousSession({
      role: 'joiner',
      handle: validHandle,
      localIdentity: idResp,
      peerDeviceId: idInit.deviceId,
      peerPublicKey: idInit.publicKey,
      kPair,
      pairCredentialRef: 'cred-1',
      send: (msg) => {
        joinerOutbox.push(msg as Record<string, unknown>);
      },
    });

    // 1. Offerer starts and sends rendezvous message
    await offererSession.start();
    expect(offererSession.getPhase()).toBe('rendezvous_sent');
    expect(offererOutbox[0]).toEqual({
      type: 'rendezvous',
      handle: validHandle,
      role: 'offerer',
    });

    // Server acknowledges offerer room creation
    await offererSession.handleMessage({ type: 'created', handle: validHandle });
    expect(offererSession.getPhase()).toBe('waiting_peer');

    // 2. Joiner starts and sends rendezvous message
    await joinerSession.start();
    expect(joinerSession.getPhase()).toBe('rendezvous_sent');
    expect(joinerOutbox[0]).toEqual({
      type: 'rendezvous',
      handle: validHandle,
      role: 'joiner',
    });

    // Server signals pairing to offerer
    await offererSession.handleMessage({ type: 'peer-joined' });
    expect(offererSession.getPhase()).toBe('authenticating');
    // Offerer should have emitted trusted_auth_init
    const initMsg = offererOutbox[1];
    expect(initMsg.type).toBe('trusted_auth_init');
    expect(initMsg.protocol_version).toBe('sendbeam/3');

    // Joiner receives trusted_auth_init
    await joinerSession.handleMessage(initMsg);
    // Joiner should have emitted trusted_auth_response and trusted_auth_confirm
    const respMsg = joinerOutbox[1];
    expect(respMsg.type).toBe('trusted_auth_response');
    expect(respMsg.status).toBe('accepted');
    const joinerConfirmMsg = joinerOutbox[2];
    expect(joinerConfirmMsg.type).toBe('trusted_auth_confirm');
    expect(joinerConfirmMsg.status).toBe('ready');

    // Offerer receives trusted_auth_response
    await offererSession.handleMessage(respMsg);
    // Offerer should have emitted trusted_auth_confirm
    const offererConfirmMsg = offererOutbox[2];
    expect(offererConfirmMsg.type).toBe('trusted_auth_confirm');
    expect(offererConfirmMsg.status).toBe('ready');

    // Mutual confirmation exchange
    await offererSession.handleMessage(joinerConfirmMsg);
    await joinerSession.handleMessage(offererConfirmMsg);

    // Both should be established!
    expect(offererSession.getPhase()).toBe('established');
    expect(joinerSession.getPhase()).toBe('established');

    const offererRes = await offererSession.result;
    const joinerRes = await joinerSession.result;

    // Verify session keys match bidirectionally
    expect(offererRes.master).toEqual(joinerRes.master);
    expect(offererRes.sendKey).toEqual(joinerRes.recvKey);
    expect(offererRes.recvKey).toEqual(joinerRes.sendKey);
    expect(offererRes.role).toBe('offerer');
    expect(joinerRes.role).toBe('joiner');
    expect(offererRes.handle).toBe(validHandle);
    expect(joinerRes.handle).toBe(validHandle);
  });

  it('fails when peer sends invalid auth tag', async () => {
    const idInit = await createDeviceIdentityFromSeed(seedInit);
    const idResp = await createDeviceIdentityFromSeed(seedResp);

    const offererSession = new OpaqueRendezvousSession({
      role: 'offerer',
      handle: validHandle,
      localIdentity: idInit,
      peerDeviceId: idResp.deviceId,
      peerPublicKey: idResp.publicKey,
      kPair,
      pairCredentialRef: 'cred-1',
      send: () => {},
    });

    await offererSession.start();
    await offererSession.handleMessage({ type: 'created', handle: validHandle });
    await offererSession.handleMessage({ type: 'peer-joined' });

    // Tampered response
    await offererSession.handleMessage({
      type: 'trusted_auth_response',
      protocol_version: 'sendbeam/3',
      status: 'accepted',
      responder_device_id: idResp.deviceId,
      ephemeral_pub: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      nonce: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      signature: '00'.repeat(64),
      auth_tag: '00'.repeat(32),
    });

    expect(offererSession.getPhase()).toBe('failed');
    await expect(offererSession.result).rejects.toThrow();
  });

  it('fails when signaling returns error or peer leaves prematurely', async () => {
    const idInit = await createDeviceIdentityFromSeed(seedInit);
    const session = new OpaqueRendezvousSession({
      role: 'offerer',
      handle: validHandle,
      localIdentity: idInit,
      peerDeviceId: 'peer-id',
      peerPublicKey: 'peer-pk',
      kPair,
      pairCredentialRef: 'cred-1',
      send: () => {},
    });

    await session.start();
    await session.handleMessage({ type: 'peer_left' });
    expect(session.getPhase()).toBe('failed');
    await expect(session.result).rejects.toThrow('peer_left');
  });
});
