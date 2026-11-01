import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  StoreOpenedBeforeReadyError,
  getStoreKeyFilePath,
  resolveStoreKeys,
  type StoreKeyDeps,
} from '../src/main/utils/store-key';

// A reversible stand-in for safeStorage: the key file must not contain the key
// in clear, and decrypting needs the same "OS secret".
function fakeSafeStorage(userData: string, overrides: Partial<StoreKeyDeps> = {}): StoreKeyDeps {
  const secret = 0x5a;
  return {
    isReady: () => true,
    isEncryptionAvailable: () => true,
    encryptString: (plain) => Buffer.from([...Buffer.from(plain)].map((b) => b ^ secret)),
    decryptString: (encrypted) => Buffer.from([...encrypted].map((b) => b ^ secret)).toString(),
    userDataPath: () => userData,
    ...overrides,
  };
}

describe('resolveStoreKeys', () => {
  let userData: string;
  const base = {
    storeName: 'config',
    fixedKey: 'open-cowork-config-stable-v1',
    legacyKeys: ['open-cowork-config-v1', 'derived-hex'],
  };

  beforeEach(() => {
    userData = fs.mkdtempSync(path.join(os.tmpdir(), 'store-key-'));
  });

  afterEach(() => {
    fs.rmSync(userData, { recursive: true, force: true });
  });

  it('creates a random protected key and keeps the fixed key for migration', () => {
    const keys = resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });

    expect(keys.protectedBySafeStorage).toBe(true);
    expect(keys.stableKey).toMatch(/^[0-9a-f]{64}$/);
    expect(keys.stableKey).not.toBe(base.fixedKey);
    expect(keys.legacyKeys).toEqual([base.fixedKey, ...base.legacyKeys]);

    const onDisk = fs.readFileSync(getStoreKeyFilePath(userData, 'config'));
    expect(onDisk.toString('utf8')).not.toContain(keys.stableKey);
  });

  it('returns the same key on the next start', () => {
    const first = resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });
    const second = resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });
    expect(second.stableKey).toBe(first.stableKey);
  });

  it('uses a separate key per store', () => {
    const config = resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });
    const remote = resolveStoreKeys({
      ...base,
      storeName: 'remote-config',
      deps: fakeSafeStorage(userData),
    });
    expect(remote.stableKey).not.toBe(config.stableKey);
  });

  it('refuses to open a store before the app is ready', () => {
    expect(() =>
      resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData, { isReady: () => false }) })
    ).toThrow(StoreOpenedBeforeReadyError);
    expect(fs.existsSync(getStoreKeyFilePath(userData, 'config'))).toBe(false);
  });

  it('keeps the fixed key when the OS keyring is unavailable and nothing was migrated', () => {
    const warn = vi.fn();
    const keys = resolveStoreKeys({
      ...base,
      warn,
      deps: fakeSafeStorage(userData, { isEncryptionAvailable: () => false }),
    });
    expect(keys).toEqual({
      stableKey: base.fixedKey,
      legacyKeys: base.legacyKeys,
      protectedBySafeStorage: false,
    });
    expect(warn).toHaveBeenCalled();
  });

  it('refuses rather than falling back when a protected key exists but the keyring is locked', () => {
    resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });
    expect(() =>
      resolveStoreKeys({
        ...base,
        deps: fakeSafeStorage(userData, { isEncryptionAvailable: () => false }),
      })
    ).toThrow(/system keyring/);
  });

  it('backs up an undecryptable key file and creates a new key', () => {
    const first = resolveStoreKeys({ ...base, deps: fakeSafeStorage(userData) });
    const warn = vi.fn();
    const second = resolveStoreKeys({
      ...base,
      warn,
      deps: fakeSafeStorage(userData, {
        decryptString: () => {
          throw new Error('DPAPI: key not valid');
        },
      }),
    });
    expect(second.stableKey).not.toBe(first.stableKey);
    expect(fs.readdirSync(userData).some((name) => name.includes('.key.unreadable-'))).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('keeps the fixed key when electron has no safeStorage (unit-test mocks)', () => {
    // No deps override and the mocked electron below has no safeStorage.
    const keys = resolveStoreKeys({ ...base });
    expect(keys.stableKey).toBe(base.fixedKey);
    expect(keys.protectedBySafeStorage).toBe(false);
  });
});

vi.mock('electron', () => ({ app: { getPath: () => os.tmpdir() } }));
