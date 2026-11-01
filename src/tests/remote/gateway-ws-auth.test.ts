import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebSocket } from 'ws';
import { RemoteGateway, checkWSAuth, isAllowedWSHandshake } from '../../main/remote/gateway';
import type { GatewayConfig } from '../../main/remote/types';

vi.mock('../../main/utils/logger', () => ({
  log: vi.fn(),
  logError: vi.fn(),
  logWarn: vi.fn(),
}));

describe('checkWSAuth', () => {
  it('rejects every non-token mode, whatever the client sends', () => {
    for (const mode of ['allowlist', 'pairing', 'open'] as const) {
      expect(checkWSAuth({ mode }, 'anything').success).toBe(false);
      expect(checkWSAuth({ mode, token: 'secret' }, 'secret').success).toBe(false);
    }
  });

  it('rejects token mode when no token is configured', () => {
    expect(checkWSAuth({ mode: 'token' }, '').success).toBe(false);
    expect(checkWSAuth({ mode: 'token', token: '' }, '').success).toBe(false);
  });

  it('accepts only the exact configured token', () => {
    const auth = { mode: 'token' as const, token: 'correct-horse' };
    expect(checkWSAuth(auth, 'correct-horse').success).toBe(true);
    expect(checkWSAuth(auth, 'correct-hors').success).toBe(false);
    expect(checkWSAuth(auth, 'correct-horse ').success).toBe(false);
    expect(checkWSAuth(auth, undefined).success).toBe(false);
    expect(checkWSAuth(auth, { token: 'correct-horse' }).success).toBe(false);
  });
});

describe('isAllowedWSHandshake', () => {
  it('refuses handshakes that carry a browser Origin', () => {
    expect(isAllowedWSHandshake('https://evil.example')).toBe(false);
    expect(isAllowedWSHandshake('http://127.0.0.1:18789')).toBe(false);
    expect(isAllowedWSHandshake('null')).toBe(false);
  });

  it('allows native clients that send no Origin', () => {
    expect(isAllowedWSHandshake(undefined)).toBe(true);
  });
});

describe('RemoteGateway WebSocket endpoint', () => {
  let gateway: RemoteGateway | undefined;

  afterEach(async () => {
    await gateway?.stop();
    gateway = undefined;
  });

  async function startGateway(auth: GatewayConfig['auth']) {
    const routeMessage = vi.fn(async () => undefined);
    const router = {
      onResponse: vi.fn(),
      routeMessage,
      getActiveSessionCount: () => 0,
    };
    const config = {
      enabled: true,
      port: 0,
      bind: '127.0.0.1',
      auth,
    } as GatewayConfig;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    gateway = new RemoteGateway(config, router as any);
    await gateway.start();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const address = (gateway as any).httpServer.address();
    return { port: address.port as number, routeMessage };
  }

  function connect(port: number, headers?: Record<string, string>) {
    return new Promise<WebSocket>((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers });
      ws.once('open', () => resolve(ws));
      ws.once('error', reject);
      ws.once('unexpected-response', (_req, res) =>
        reject(new Error(`handshake rejected: ${res.statusCode}`))
      );
    });
  }

  function nextMessage(ws: WebSocket, type: string) {
    return new Promise<{ type: string; payload: Record<string, unknown> }>((resolve) => {
      const onMessage = (data: Buffer) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === type) {
          ws.off('message', onMessage);
          resolve(msg);
        }
      };
      ws.on('message', onMessage);
    });
  }

  it('refuses a handshake coming from a web page', async () => {
    const { port } = await startGateway({ mode: 'allowlist', allowlist: [] });
    await expect(connect(port, { Origin: 'https://evil.example' })).rejects.toThrow(
      /handshake rejected/
    );
  });

  it('does not authenticate or route messages in the default allowlist mode', async () => {
    const { port, routeMessage } = await startGateway({ mode: 'allowlist', allowlist: [] });
    const ws = await connect(port);
    const authResult = nextMessage(ws, 'auth_result');
    ws.send(JSON.stringify({ type: 'auth', payload: {} }));
    expect((await authResult).payload.success).toBe(false);

    const error = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'message', payload: { text: 'read ~/.ssh/id_rsa' } }));
    expect((await error).payload.error).toBe('Not authenticated');
    expect(routeMessage).not.toHaveBeenCalled();
    ws.close();
  });

  it('routes messages only after the correct token in token mode', async () => {
    const { port, routeMessage } = await startGateway({ mode: 'token', token: 's3cret' });
    const ws = await connect(port);

    const bad = nextMessage(ws, 'auth_result');
    ws.send(JSON.stringify({ type: 'auth', payload: { token: 'wrong' } }));
    expect((await bad).payload.success).toBe(false);

    const good = nextMessage(ws, 'auth_result');
    ws.send(JSON.stringify({ type: 'auth', payload: { token: 's3cret' } }));
    expect((await good).payload.success).toBe(true);

    ws.send(JSON.stringify({ type: 'message', payload: { text: 'hello' } }));
    await vi.waitFor(() => expect(routeMessage).toHaveBeenCalledTimes(1));
    ws.close();
  });
});
