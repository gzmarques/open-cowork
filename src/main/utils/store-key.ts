/**
 * Per-install encryption keys for the electron-store files that hold secrets
 * (API keys, gateway/channel tokens, MCP server env and headers).
 *
 * Earlier releases encrypted those files with a key written in the source code
 * ('open-cowork-config-stable-v1', ...), so any program able to read the file
 * could decrypt it. Instead, each store now gets a random 256-bit key that is
 * itself encrypted with Electron's safeStorage (DPAPI on Windows, Keychain on
 * macOS, the Secret Service/kwallet on Linux) and kept next to the store as
 * `<store>.key`. The old fixed key stays in the legacy list so existing files
 * are migrated on first open.
 *
 * safeStorage only works after the app is ready (Windows and Linux), so these
 * stores must not be opened earlier. Opening one too early throws instead of
 * silently falling back, because falling back to the fixed key after a store
 * was migrated would make it unreadable.
 *
 * When safeStorage is unavailable (Linux without a keyring), the fixed key is
 * still used, as before, unless a protected key file already exists.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app, safeStorage } from 'electron';

type Logger = (...args: unknown[]) => void;

export interface StoreKeyDeps {
  isReady: () => boolean;
  isEncryptionAvailable: () => boolean;
  encryptString: (plain: string) => Buffer;
  decryptString: (encrypted: Buffer) => string;
  userDataPath: () => string;
}

export interface ResolveStoreKeysOptions {
  /** electron-store `name`, used for the key file name. */
  storeName: string;
  /** The fixed key earlier releases used as the stable key. */
  fixedKey: string;
  /** Older keys still accepted for migration. */
  legacyKeys: string[];
  log?: Logger;
  warn?: Logger;
  /** Overrides for tests. */
  deps?: StoreKeyDeps;
}

export interface ResolvedStoreKeys {
  stableKey: string;
  legacyKeys: string[];
  protectedBySafeStorage: boolean;
}

export class StoreOpenedBeforeReadyError extends Error {
  constructor(storeName: string) {
    super(
      `[StoreKey] The "${storeName}" store was opened before the app was ready. ` +
        'Its encryption key is protected by safeStorage, which is only available ' +
        'after app.whenReady(); move this access after startup.'
    );
    this.name = 'StoreOpenedBeforeReadyError';
  }
}

function defaultDeps(): StoreKeyDeps | null {
  // Unit tests often mock 'electron' with a bare `app`; without safeStorage
  // there is nothing to protect the key with, so keep the fixed key.
  if (
    !app ||
    typeof app.isReady !== 'function' ||
    typeof app.getPath !== 'function' ||
    !safeStorage ||
    typeof safeStorage.isEncryptionAvailable !== 'function'
  ) {
    return null;
  }
  return {
    isReady: () => app.isReady(),
    isEncryptionAvailable: () => safeStorage.isEncryptionAvailable(),
    encryptString: (plain) => safeStorage.encryptString(plain),
    decryptString: (encrypted) => safeStorage.decryptString(encrypted),
    userDataPath: () => app.getPath('userData'),
  };
}

export function getStoreKeyFilePath(userDataPath: string, storeName: string): string {
  return path.join(userDataPath, `${storeName}.key`);
}

function writeFileAtomic(filePath: string, data: Buffer): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tempPath, data, { mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

function uniqueValues(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function resolveStoreKeys(options: ResolveStoreKeysOptions): ResolvedStoreKeys {
  const { storeName, fixedKey, log, warn } = options;
  const legacyKeys = uniqueValues(options.legacyKeys.filter((key) => key !== fixedKey));
  const fixed: ResolvedStoreKeys = {
    stableKey: fixedKey,
    legacyKeys,
    protectedBySafeStorage: false,
  };

  const deps = options.deps ?? defaultDeps();
  if (!deps) {
    return fixed;
  }

  if (!deps.isReady()) {
    throw new StoreOpenedBeforeReadyError(storeName);
  }

  const keyFilePath = getStoreKeyFilePath(deps.userDataPath(), storeName);
  const keyFileExists = fs.existsSync(keyFilePath);

  if (!deps.isEncryptionAvailable()) {
    if (keyFileExists) {
      // The store was migrated to a protected key that cannot be unlocked now
      // (keyring locked or missing). Refuse rather than recreate an empty store.
      throw new Error(
        `[StoreKey] "${storeName}" is protected by the system keyring, which is not ` +
          'available right now. Unlock or start the keyring and restart the app.'
      );
    }
    warn?.(
      `[StoreKey] safeStorage unavailable; "${storeName}" keeps the built-in key ` +
        '(secrets are not protected by the OS keyring on this system)'
    );
    return fixed;
  }

  const protectedKeys = (stableKey: string): ResolvedStoreKeys => ({
    stableKey,
    legacyKeys: uniqueValues([fixedKey, ...legacyKeys]),
    protectedBySafeStorage: true,
  });

  if (keyFileExists) {
    try {
      const key = deps.decryptString(fs.readFileSync(keyFilePath));
      if (/^[0-9a-f]{64}$/.test(key)) {
        return protectedKeys(key);
      }
      throw new Error('key file has unexpected content');
    } catch (error) {
      // The OS can no longer decrypt the key (e.g. Windows profile reset).
      // Keep the old key file for recovery and start over with a new key;
      // the store itself is backed up by the rotation helper when unreadable.
      const backupPath = `${keyFilePath}.unreadable-${Date.now()}.bak`;
      try {
        fs.renameSync(keyFilePath, backupPath);
      } catch {
        // Best effort; a new key file is written below either way.
      }
      warn?.(`[StoreKey] Could not unlock the "${storeName}" key; created a new one`, {
        backupPath,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const key = crypto.randomBytes(32).toString('hex');
  writeFileAtomic(keyFilePath, deps.encryptString(key));
  log?.(`[StoreKey] Created a safeStorage-protected key for "${storeName}"`);
  return protectedKeys(key);
}
