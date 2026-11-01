import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const host = vi.hoisted(() => ({ directory: '', ready: true }));

// Keep electron-store and Conf real; replace only the Electron host API, with a
// reversible stand-in for safeStorage.
vi.mock('electron', () => {
  const app = {
    isPackaged: false,
    isReady: () => host.ready,
    getPath: () => host.directory,
    getVersion: () => '3.3.1',
  };
  const safeStorage = {
    isEncryptionAvailable: () => true,
    encryptString: (plain: string) => Buffer.from(plain).reverse(),
    decryptString: (encrypted: Buffer) => Buffer.from(encrypted).reverse().toString(),
  };
  const ipcMain = { on: vi.fn() };
  return { app, safeStorage, ipcMain, default: { app, safeStorage, ipcMain } };
});
vi.mock('../src/main/utils/logger', () => ({ log: vi.fn(), logError: vi.fn(), logWarn: vi.fn() }));

const OLD_FIXED_KEY = 'open-cowork-config-stable-v1';
const SECRET = 'sk-ant-api03-MIGRATION-TEST-KEY';

async function writeWithOldFixedKey() {
  const { default: Store } = await import('electron-store');
  const store = new Store<Record<string, unknown>>({
    name: 'config',
    encryptionKey: OLD_FIXED_KEY,
  });
  store.set('provider', 'anthropic');
  store.set('apiKey', SECRET);
  store.set('isConfigured', true);
  return store.path;
}

async function canReadWithOldFixedKey(): Promise<boolean> {
  const { default: Store } = await import('electron-store');
  try {
    const store = new Store<Record<string, unknown>>({
      name: 'config',
      encryptionKey: OLD_FIXED_KEY,
    });
    return store.get('apiKey') === SECRET;
  } catch {
    return false;
  }
}

describe('ConfigStore encryption key migration (real electron-store)', () => {
  beforeEach(() => {
    vi.resetModules();
    host.directory = mkdtempSync(path.join(tmpdir(), 'open-cowork-key-migration-'));
    host.ready = true;
  });

  afterEach(() => {
    rmSync(host.directory, { recursive: true, force: true });
  });

  it('moves an existing config from the built-in key to a protected key without losing data', async () => {
    const storePath = await writeWithOldFixedKey();
    expect(await canReadWithOldFixedKey()).toBe(true);

    vi.resetModules();
    const { ConfigStore } = await import('../src/main/config/config-store');
    const store = new ConfigStore();
    expect(store.get('apiKey')).toBe(SECRET);
    expect(store.get('provider')).toBe('anthropic');

    // The key file exists and the store no longer opens with the built-in key.
    expect(readdirSync(host.directory)).toContain('config.key');
    vi.resetModules();
    expect(await canReadWithOldFixedKey()).toBe(false);
    expect(readFileSync(storePath).toString('utf8')).not.toContain(SECRET);

    // A fresh start reads the migrated store with the protected key.
    vi.resetModules();
    const { ConfigStore: Reloaded } = await import('../src/main/config/config-store');
    expect(new Reloaded().get('apiKey')).toBe(SECRET);
  });

  it('does not touch the config when it is accessed before the app is ready', async () => {
    const storePath = await writeWithOldFixedKey();
    const before = readFileSync(storePath);

    vi.resetModules();
    host.ready = false;
    const { ConfigStore } = await import('../src/main/config/config-store');
    // Importing and constructing must not open the file.
    const store = new ConfigStore();
    expect(() => store.get('apiKey')).toThrow(/before the app was ready/);

    expect(readFileSync(storePath).equals(before)).toBe(true);
    expect(readdirSync(host.directory)).not.toContain('config.key');

    // Once ready, the same instance opens and migrates normally.
    host.ready = true;
    expect(store.get('apiKey')).toBe(SECRET);
  });
});
