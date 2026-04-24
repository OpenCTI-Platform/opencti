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

import { encryptDatabaseValue, decryptDatabaseValue } from '../../../src/utils/platformCrypto';

describe('platformCrypto – encryptDatabaseValue / decryptDatabaseValue', () => {
  it('should encrypt and decrypt a value round-trip', async () => {
    const original = 'my-secret-bearer-token';
    const encrypted = await encryptDatabaseValue(original);
    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe(original);
    // Encrypted value should be base64
    expect(encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const decrypted = await decryptDatabaseValue(encrypted!);
    expect(decrypted).toBe(original);
  });

  it('should return falsy values unchanged', async () => {
    expect(await encryptDatabaseValue(null)).toBeNull();
    expect(await encryptDatabaseValue(undefined)).toBeUndefined();
    expect(await encryptDatabaseValue('')).toBe('');
    expect(await decryptDatabaseValue(null)).toBeNull();
    expect(await decryptDatabaseValue(undefined)).toBeUndefined();
    expect(await decryptDatabaseValue('')).toBe('');
  });

  it('should produce different ciphertexts for the same plaintext (random IV)', async () => {
    const original = 'same-plaintext-value';
    const encrypted1 = await encryptDatabaseValue(original);
    const encrypted2 = await encryptDatabaseValue(original);
    // AES-GCM uses random IV so ciphertexts differ
    expect(encrypted1).not.toBe(encrypted2);
    // Both must decrypt to the same original
    expect(await decryptDatabaseValue(encrypted1!)).toBe(original);
    expect(await decryptDatabaseValue(encrypted2!)).toBe(original);
  });
});
