/**
 * Browser opaque rendezvous controller (V19-PR09).
 * Bridges WebSocket signaling with pure OpaqueRendezvousSession state machine for sendbeam/3.
 */

import {
  OpaqueRendezvousSession,
  deriveTransferKeys,
  type DeviceIdentity,
  type Feature,
  type OpaqueRendezvousPhase,
  type RendezvousResult,
  type Role,
  type SignalMsg,
} from '@sendbeam/protocol';
import { SignalingClient, type BackoffOptions, type SignalChannel } from '../signaling/client.js';

function defaultSignalingUrl(): string {
  if (typeof window !== 'undefined' && window.location) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws`;
  }
  return 'ws://localhost:8443/ws';
}

export interface OpaqueControllerOptions {
  url?: string;
  role: Role;
  handle: string;
  localIdentity: DeviceIdentity;
  peerDeviceId: string;
  peerPublicKey: string | Uint8Array;
  kPair: Uint8Array;
  pairCredentialRef: string;
  localCapabilities?: string[];
  onPhase?: (phase: OpaqueRendezvousPhase) => void;
  backoff?: Partial<BackoffOptions>;
  timeoutMs?: number;
}

export interface OpaqueRendezvousController {
  readonly handle: string;
  readonly phase: OpaqueRendezvousPhase;
  readonly done: Promise<RendezvousResult>;
  cancel(reason?: string): void;
  adoptSignaling(): SignalChannel;
}

export function createOpaqueRendezvous(opts: OpaqueControllerOptions): OpaqueRendezvousController {
  const url = opts.url ?? defaultSignalingUrl();
  let route: (msg: SignalMsg) => void = (msg) => {
    void session.handleMessage(msg);
  };
  let routeBinary: (frame: ArrayBuffer) => void = () => {
    // Unexpected binary frame before transfer
  };
  let routeClose: (err: Error) => void = () => {
    // Socket closed unexpectedly
  };
  let adopted = false;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;

  const client = new SignalingClient({
    url,
    onMessage: (msg) => route(msg),
    onBinary: (frame) => routeBinary(frame),
    onClose: (clean, code, reason) => {
      routeClose(
        new Error(clean ? `signaling closed (${code})` : `signaling lost (${code} ${reason})`),
      );
    },
    onError: () => {
      // Ignored here; handled by session or close
    },
    ...(opts.backoff !== undefined ? { backoff: opts.backoff } : {}),
  });

  const session = new OpaqueRendezvousSession({
    role: opts.role,
    handle: opts.handle,
    localIdentity: opts.localIdentity,
    peerDeviceId: opts.peerDeviceId,
    peerPublicKey: opts.peerPublicKey,
    kPair: opts.kPair,
    pairCredentialRef: opts.pairCredentialRef,
    ...(opts.localCapabilities ? { localCapabilities: opts.localCapabilities } : {}),
    send: (msg) => client.send(msg as SignalMsg),
    ...(opts.onPhase ? { onPhase: opts.onPhase } : {}),
    ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}),
  });

  const donePromise = (async (): Promise<RendezvousResult> => {
    let timeoutPromise: Promise<never> | undefined;
    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timeoutPromise = new Promise<never>((_, reject) => {
        timeoutTimer = setTimeout(() => {
          reject(new Error('timeout: peer unreachable or offline'));
        }, opts.timeoutMs);
      });
    }

    try {
      await client.connect();
      await session.start();

      const ores = timeoutPromise
        ? await Promise.race([session.result, timeoutPromise])
        : await session.result;

      clearTimeout(timeoutTimer);
      const keys = await deriveTransferKeys(ores.master);

      const features = (
        ores.negotiatedCaps && ores.negotiatedCaps.length > 0
          ? ores.negotiatedCaps
          : ['transfer.v1', 'padding']
      ) as Feature[];

      const res: RendezvousResult = {
        role: ores.role,
        code: ores.handle,
        master: ores.master,
        keys,
        authKeys: {
          sign: ores.sendKey,
          verify: ores.recvKey,
        },
        localCaps: {
          version: 'sendbeam/3',
          maxFrame: 65536,
          blockSize: 1048576,
          features,
          sinkHints: [],
        },
        remoteCaps: {
          version: 'sendbeam/3',
          maxFrame: 65536,
          blockSize: 1048576,
          features,
          sinkHints: [],
        },
        sendCounter: 0,
        recvCounter: 0,
      };

      // Defer auto-close so adoptSignaling can be called
      setTimeout(() => void (adopted || client.close()), 0);
      return res;
    } catch (err: unknown) {
      clearTimeout(timeoutTimer);
      client.close();
      throw err instanceof Error ? err : new Error(String(err));
    }
  })();

  return {
    get handle() {
      return opts.handle;
    },
    get phase() {
      return session.getPhase();
    },
    done: donePromise,
    cancel: () => {
      clearTimeout(timeoutTimer);
      client.close();
    },
    adoptSignaling: () => {
      adopted = true;
      return {
        send: (msg) => client.send(msg),
        sendBinary: (frame) => client.sendBinary(frame),
        onMessage: (h) => {
          route = h;
        },
        onBinary: (h) => {
          routeBinary = h;
        },
        onClose: (h) => {
          routeClose = h;
        },
        setResume: (room, role) => client.setResume(room, role),
        close: () => client.close(),
      };
    },
  };
}

export function opaqueOffer(
  opts: Omit<OpaqueControllerOptions, 'role'>,
): OpaqueRendezvousController {
  return createOpaqueRendezvous({ ...opts, role: 'offerer' });
}

export function opaqueJoin(
  opts: Omit<OpaqueControllerOptions, 'role'>,
): OpaqueRendezvousController {
  return createOpaqueRendezvous({ ...opts, role: 'joiner' });
}
