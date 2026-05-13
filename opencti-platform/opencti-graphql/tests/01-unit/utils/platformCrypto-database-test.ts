import { describe, expect, it, vi } from 'vitest';

// Mock nconf with a valid 32-byte encryption key (base64-encoded)
// "0123456789abcdef0123456789abcdef" = 32 bytes
vi.mock('nconf', () => ({
  default: {
    get: (key: string) => {
      if (key === 'app:encryption_key') return 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';
      return undefined;
    },
  },
}));

vi.mock('../../../src/config/conf', () => ({
  confNameToEnvName: () => 'APP__ENCRYPTION_KEY',
}));

vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn().mockResolvedValue({ value: undefined }),
}));

import {
  encryptIngestionCredential,
  decryptIngestionCredential,
  isIngestionCredentialEncrypted,
  encryptSynchronizerCredential,
  decryptSynchronizerCredential,
  isSynchronizerCredentialEncrypted,
} from '../../../src/utils/platformCrypto';

describe('platformCrypto – encryptIngestionCredential / decryptIngestionCredential', () => {
  it('should encrypt and decrypt a value round-trip', async () => {
    const original = 'my-secret-bearer-token';
    const encrypted = await encryptIngestionCredential(original);
    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe(original);
    // Encrypted value should be base64
    expect(encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const decrypted = await decryptIngestionCredential(encrypted!);
    expect(decrypted).toBe(original);
  });

  it('should return falsy values unchanged', async () => {
    expect(await encryptIngestionCredential(null)).toBeNull();
    expect(await encryptIngestionCredential(undefined)).toBeUndefined();
    expect(await encryptIngestionCredential('')).toBe('');
    expect(await decryptIngestionCredential(null)).toBeNull();
    expect(await decryptIngestionCredential(undefined)).toBeUndefined();
    expect(await decryptIngestionCredential('')).toBe('');
  });

  it('should produce different ciphertexts for the same plaintext (random IV)', async () => {
    const original = 'same-plaintext-value';
    const encrypted1 = await encryptIngestionCredential(original);
    const encrypted2 = await encryptIngestionCredential(original);
    // AES-GCM uses random IV so ciphertexts differ
    expect(encrypted1).not.toBe(encrypted2);
    // Both must decrypt to the same original
    expect(await decryptIngestionCredential(encrypted1!)).toBe(original);
    expect(await decryptIngestionCredential(encrypted2!)).toBe(original);
  });
});

describe('platformCrypto – isIngestionCredentialEncrypted', () => {
  it('should return true when value is encrypted with the ingestion key', async () => {
    const plaintext = 'my-api-key';
    const encrypted = await encryptIngestionCredential(plaintext);
    expect(await isIngestionCredentialEncrypted(encrypted!)).toBe(true);
  });

  it('should return false when value is plain text', async () => {
    expect(await isIngestionCredentialEncrypted('plain-text-token')).toBe(false);
  });
});

describe('platformCrypto – encryptSynchronizerCredential / decryptSynchronizerCredential', () => {
  it('should encrypt and decrypt a value round-trip', async () => {
    const original = 'my-synchronizer-token';
    const encrypted = await encryptSynchronizerCredential(original);
    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe(original);
    expect(encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const decrypted = await decryptSynchronizerCredential(encrypted!);
    expect(decrypted).toBe(original);
  });

  it('should return falsy values unchanged', async () => {
    expect(await encryptSynchronizerCredential(null)).toBeNull();
    expect(await encryptSynchronizerCredential(undefined)).toBeUndefined();
    expect(await encryptSynchronizerCredential('')).toBe('');
    expect(await decryptSynchronizerCredential(null)).toBeNull();
    expect(await decryptSynchronizerCredential(undefined)).toBeUndefined();
    expect(await decryptSynchronizerCredential('')).toBe('');
  });
});

describe('platformCrypto – isSynchronizerCredentialEncrypted', () => {
  it('should return true when value is encrypted with the synchronizer key', async () => {
    const plaintext = 'my-stream-token';
    const encrypted = await encryptSynchronizerCredential(plaintext);
    expect(await isSynchronizerCredentialEncrypted(encrypted!)).toBe(true);
  });

  it('should return false when value is plain text', async () => {
    expect(await isSynchronizerCredentialEncrypted('plain-text-token')).toBe(false);
  });
});
