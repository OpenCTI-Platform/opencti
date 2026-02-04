import { describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';
import { createCryptoKeyFactory } from '../../../src/utils/platformCrypto';

describe('platformCrypto: key derivation', () => {
  const testSeed = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes

  it('should create a crypto key factory with valid seed', () => {
    expect(() => createCryptoKeyFactory(testSeed)).not.toThrow();
  });

  it('should throw error if seed is too short', () => {
    const shortSeed = Buffer.from('a'.repeat(30), 'hex'); // 15 bytes
    expect(() => createCryptoKeyFactory(shortSeed)).toThrow(/must have at least 32 bytes/);
  });

  it('should derive AES key with valid path', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const aesKey = await factory.deriveAesKey(['test', 'path'], 1);
    expect(aesKey).toHaveProperty('encrypt');
    expect(aesKey).toHaveProperty('decrypt');
  });

  it('should derive Ed25519 keypair with valid path', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'path'], 1);
    expect(keyPair).toHaveProperty('publicKeys');
    expect(keyPair).toHaveProperty('sign');
    expect(keyPair).toHaveProperty('verify');
    expect(keyPair).toHaveProperty('signJwt');
    expect(keyPair).toHaveProperty('verifyJwt');
  });

  it('should allow empty derivation path (extended with algo internally)', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey([], 1);
    expect(key).toHaveProperty('encrypt');
    expect(key).toHaveProperty('decrypt');
  });

  it('should throw error for derivation path with empty string', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    await expect(factory.deriveAesKey(['test', '', 'path'], 1)).rejects.toThrow(/Invalid derivation path/);
  });

  it('should throw error for derivation path containing colon', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    await expect(factory.deriveAesKey(['test:invalid', 'path'], 1)).rejects.toThrow(/Invalid derivation path/);
  });

  it('should throw error for non-positive version', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    await expect(factory.deriveAesKey(['test', 'path'], 0)).rejects.toThrow(/Version must be positive/);
    await expect(factory.deriveAesKey(['test', 'path'], -1)).rejects.toThrow(/Version must be positive/);
  });

  it('should derive different keys for different paths', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key1 = await factory.deriveAesKey(['path', 'one'], 1);
    const key2 = await factory.deriveAesKey(['path', 'two'], 1);

    const testData = Buffer.from('test data');
    const encrypted1 = await key1.encrypt(testData);
    const encrypted2 = await key2.encrypt(testData);

    // Different paths should produce different encrypted outputs
    expect(encrypted1.equals(encrypted2)).toBe(false);

    // Key1 cannot decrypt data encrypted with key2
    await expect(key1.decrypt(encrypted2)).rejects.toThrow();
  });

  it('should derive different keys for different versions', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyV1 = await factory.deriveAesKey(['test', 'path'], 1);
    const keyV2 = await factory.deriveAesKey(['test', 'path'], 2);

    const testData = Buffer.from('test data');
    const encryptedV1 = await keyV1.encrypt(testData);
    const encryptedV2 = await keyV2.encrypt(testData);

    // Different versions should produce different encrypted outputs
    expect(encryptedV1.equals(encryptedV2)).toBe(false);

    // V1 key cannot decrypt data encrypted with V2 key
    await expect(keyV1.decrypt(encryptedV2)).rejects.toThrow(/Invalid kid for decryption/);
  });
});

describe('platformCrypto: AES encryption and decryption', () => {
  const testSeed = Buffer.from('a'.repeat(64), 'hex');

  it('should encrypt and decrypt data successfully', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'encryption'], 1);

    const plaintext = Buffer.from('Hello, World!');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should handle empty data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'empty'], 1);

    const plaintext = Buffer.from('');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should handle large data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'large'], 1);

    const plaintext = Buffer.from('x'.repeat(10000));
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should handle binary data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'binary'], 1);

    const plaintext = Buffer.from([0x00, 0x01, 0xFF, 0xAB, 0xCD, 0xEF]);
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should produce different ciphertext for same plaintext (due to random IV)', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'random'], 1);

    const plaintext = Buffer.from('Same data');
    const encrypted1 = await key.encrypt(plaintext);
    const encrypted2 = await key.encrypt(plaintext);

    // Same plaintext should produce different ciphertext (random IV)
    expect(encrypted1.equals(encrypted2)).toBe(false);

    // Both should decrypt to the same plaintext
    const decrypted1 = await key.decrypt(encrypted1);
    const decrypted2 = await key.decrypt(encrypted2);
    expect(decrypted1.equals(plaintext)).toBe(true);
    expect(decrypted2.equals(plaintext)).toBe(true);
  });

  it('should throw error for data too short', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'short'], 1);

    const invalidData = Buffer.from([0x01, 0x02, 0x03]); // Too short
    await expect(key.decrypt(invalidData)).rejects.toThrow(/Unsupported encrypted data/);
  });

  it('should throw error for invalid encoding version', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'version'], 1);

    const plaintext = Buffer.from('test');
    const encrypted = await key.encrypt(plaintext);

    // Corrupt the version byte
    encrypted[0] = 0xFF;

    await expect(key.decrypt(encrypted)).rejects.toThrow(/Unsupported encrypted data encoding version/);
  });

  it('should throw error for wrong kid', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key1 = await factory.deriveAesKey(['test', 'key1'], 1);
    const key2 = await factory.deriveAesKey(['test', 'key2'], 1);

    const plaintext = Buffer.from('test');
    const encrypted = await key1.encrypt(plaintext);

    await expect(key2.decrypt(encrypted)).rejects.toThrow(/Invalid kid for decryption/);
  });

  it('should throw error for corrupted data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'corrupt'], 1);

    const plaintext = Buffer.from('test');
    const encrypted = await key.encrypt(plaintext);

    // Corrupt the ciphertext
    encrypted[encrypted.length - 1] ^= 0xFF;

    await expect(key.decrypt(encrypted)).rejects.toThrow();
  });

  it('should support AAD (Additional Authenticated Data)', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const aad = Buffer.from('metadata');
    const key = await factory.deriveAesKey(['test', 'aad'], 1, aad);

    const plaintext = Buffer.from('secret data');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should fail decryption with wrong AAD', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const aad1 = Buffer.from('metadata1');
    const aad2 = Buffer.from('metadata2');

    const keyWithAad1 = await factory.deriveAesKey(['test', 'aad1'], 1, aad1);
    const keyWithAad2 = await factory.deriveAesKey(['test', 'aad1'], 1, aad2);

    const plaintext = Buffer.from('secret data');
    const encrypted = await keyWithAad1.encrypt(plaintext);

    await expect(keyWithAad2.decrypt(encrypted)).rejects.toThrow();
  });
});

describe('platformCrypto: Ed25519 signing and verification', () => {
  const testSeed = Buffer.from('a'.repeat(64), 'hex');

  it('should sign and verify data successfully', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'signing'], 1);

    const data = Buffer.from('Hello, World!');
    const signature = await keyPair.sign(data);
    const isValid = await keyPair.verify(data, signature);

    expect(isValid).toBe(true);
  });

  it('should fail verification with wrong data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'verify'], 1);

    const data = Buffer.from('Hello, World!');
    const signature = await keyPair.sign(data);

    const wrongData = Buffer.from('Hello, World?');
    const isValid = await keyPair.verify(wrongData, signature);

    expect(isValid).toBe(false);
  });

  it('should handle empty data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'empty'], 1);

    const data = Buffer.from('');
    const signature = await keyPair.sign(data);
    const isValid = await keyPair.verify(data, signature);

    expect(isValid).toBe(true);
  });

  it('should handle large data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'large'], 1);

    const data = Buffer.from('x'.repeat(10000));
    const signature = await keyPair.sign(data);
    const isValid = await keyPair.verify(data, signature);

    expect(isValid).toBe(true);
  });

  it('should produce deterministic signatures for same data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'deterministic'], 1);

    const data = Buffer.from('Same data');
    const signature1 = await keyPair.sign(data);
    const signature2 = await keyPair.sign(data);

    // Ed25519 signatures are deterministic
    expect(signature1.equals(signature2)).toBe(true);
  });

  it('should throw error for signature too short', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'short'], 1);

    const data = Buffer.from('test');
    const invalidSignature = Buffer.from([0x01, 0x02]); // Too short

    await expect(keyPair.verify(data, invalidSignature)).rejects.toThrow(/Invalid signature format/);
  });

  it('should throw error for invalid encoding version', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'version'], 1);

    const data = Buffer.from('test');
    const signature = await keyPair.sign(data);

    // Corrupt the version byte
    signature[0] = 0xFF;

    await expect(keyPair.verify(data, signature)).rejects.toThrow(/Unsupported signature encoding version/);
  });

  it('should throw error for wrong kid', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair1 = await factory.deriveEd25519KeyPair(['test', 'key1'], 1);
    const keyPair2 = await factory.deriveEd25519KeyPair(['test', 'key2'], 1);

    const data = Buffer.from('test');
    const signature = await keyPair1.sign(data);

    await expect(keyPair2.verify(data, signature)).rejects.toThrow(/Invalid kid for signature verification/);
  });

  it('should have public keys with correct kid', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'pubkey'], 1);

    expect(keyPair.publicKeys).toBeDefined();
    expect(Object.keys(keyPair.publicKeys)).toHaveLength(1);

    const kid = Object.keys(keyPair.publicKeys)[0];
    expect(kid).toMatch(/^[0-9a-f]{16}$/); // 8 bytes = 16 hex chars
  });

  it('should produce different signatures for different key versions', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPairV1 = await factory.deriveEd25519KeyPair(['test', 'path'], 1);
    const keyPairV2 = await factory.deriveEd25519KeyPair(['test', 'path'], 2);

    const data = Buffer.from('test data');
    const signatureV1 = await keyPairV1.sign(data);
    const signatureV2 = await keyPairV2.sign(data);

    // Different versions should produce different signatures
    expect(signatureV1.equals(signatureV2)).toBe(false);

    // V1 key cannot verify signature from V2 key
    await expect(keyPairV1.verify(data, signatureV2)).rejects.toThrow(/Invalid kid for signature verification/);
  });
});

describe('platformCrypto: JWT signing and verification', () => {
  const testSeed = Buffer.from('a'.repeat(64), 'hex');

  it('should sign and verify JWT successfully', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt'], 1);

    const jwt = new SignJWT({ sub: 'user123', name: 'Test User' })
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);

    const verified = await keyPair.verifyJwt(token);
    expect(verified.payload.sub).toBe('user123');
    expect(verified.payload.name).toBe('Test User');
  });

  it('should include kid in JWT header', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-kid'], 1);

    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);
    const verified = await keyPair.verifyJwt(token);

    expect(verified.protectedHeader.kid).toBeDefined();
    expect(verified.protectedHeader.kid).toMatch(/^[0-9a-f]{16}$/);
    expect(verified.protectedHeader.alg).toBe('EdDSA');
  });

  it('should verify JWT with custom options', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-options'], 1);

    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuer('test-issuer')
      .setAudience('test-audience')
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);
    const verified = await keyPair.verifyJwt(token, {
      issuer: 'test-issuer',
      audience: 'test-audience',
    });

    expect(verified.payload.iss).toBe('test-issuer');
    expect(verified.payload.aud).toBe('test-audience');
  });

  it('should fail verification with wrong issuer', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-issuer'], 1);

    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuer('correct-issuer')
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);

    await expect(
      keyPair.verifyJwt(token, { issuer: 'wrong-issuer' }),
    ).rejects.toThrow();
  });

  it('should fail verification with expired token', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-expired'], 1);

    // Create a token that already expired 1 hour ago
    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600) // Issued 1 hour ago
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1); // Expired 1 second ago

    const token = await keyPair.signJwt(jwt);

    await expect(keyPair.verifyJwt(token)).rejects.toThrow();
  });

  it('should fail verification with tampered token', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-tamper'], 1);

    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);

    // Tamper with the token
    const parts = token.split('.');
    const tamperedPayload = Buffer.from(parts[1], 'base64url').toString();
    const modifiedPayload = tamperedPayload.replace('user123', 'user456');
    parts[1] = Buffer.from(modifiedPayload).toString('base64url');
    const tamperedToken = parts.join('.');

    await expect(keyPair.verifyJwt(tamperedToken)).rejects.toThrow();
  });

  it('should not verify JWT signed with different key', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair1 = await factory.deriveEd25519KeyPair(['test', 'jwt1'], 1);
    const keyPair2 = await factory.deriveEd25519KeyPair(['test', 'jwt2'], 1);

    const jwt = new SignJWT({ sub: 'user123' })
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair1.signJwt(jwt);

    await expect(keyPair2.verifyJwt(token)).rejects.toThrow();
  });

  it('should handle complex JWT payloads', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const keyPair = await factory.deriveEd25519KeyPair(['test', 'jwt-complex'], 1);

    const complexPayload = {
      sub: 'user123',
      name: 'Test User',
      roles: ['admin', 'user'],
      metadata: {
        organizationId: 'org-456',
        permissions: ['read', 'write', 'delete'],
      },
    };

    const jwt = new SignJWT(complexPayload)
      .setIssuedAt()
      .setExpirationTime('2h');

    const token = await keyPair.signJwt(jwt);
    const verified = await keyPair.verifyJwt(token);

    expect(verified.payload.sub).toBe('user123');
    expect(verified.payload.roles).toEqual(['admin', 'user']);
    expect(verified.payload.metadata).toEqual({
      organizationId: 'org-456',
      permissions: ['read', 'write', 'delete'],
    });
  });
});

describe('platformCrypto: edge cases and error handling', () => {
  const testSeed = Buffer.from('a'.repeat(64), 'hex');

  it('should handle concurrent operations', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'concurrent'], 1);

    const plaintext = Buffer.from('concurrent test');
    const operations = Array.from({ length: 10 }, async () => {
      const encrypted = await key.encrypt(plaintext);
      return key.decrypt(encrypted);
    });

    const results = await Promise.all(operations);
    results.forEach((decrypted) => {
      expect(decrypted.equals(plaintext)).toBe(true);
    });
  });

  it('should handle special characters in plaintext', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'special'], 1);

    const specialChars = Buffer.from('!@#$%^&*()_+-=[]{}|;:\'",.<>?/`~\n\r\t');
    const encrypted = await key.encrypt(specialChars);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(specialChars)).toBe(true);
  });

  it('should handle Unicode data', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'unicode'], 1);

    const unicode = Buffer.from('Hello 世界 🌍 Привет مرحبا');
    const encrypted = await key.encrypt(unicode);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(unicode)).toBe(true);
  });

  it('should create factory with exactly 32 bytes seed', () => {
    const seed32 = Buffer.from('a'.repeat(64), 'hex'); // exactly 32 bytes
    expect(() => createCryptoKeyFactory(seed32)).not.toThrow();
  });

  it('should create factory with more than 32 bytes seed', () => {
    const largeSeed = Buffer.from('a'.repeat(128), 'hex'); // 64 bytes
    expect(() => createCryptoKeyFactory(largeSeed)).not.toThrow();
  });

  it('should handle derivation paths with special characters (except colon)', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test_path', 'with-dashes', 'and.dots', 'and/slashes'], 1);

    const plaintext = Buffer.from('test');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should handle very long derivation paths', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const longPath = Array.from({ length: 20 }, (_, i) => `segment${i}`);
    const key = await factory.deriveAesKey(longPath, 1);

    const plaintext = Buffer.from('test');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should handle high version numbers', async () => {
    const factory = createCryptoKeyFactory(testSeed);
    const key = await factory.deriveAesKey(['test', 'path'], 999999);

    const plaintext = Buffer.from('test');
    const encrypted = await key.encrypt(plaintext);
    const decrypted = await key.decrypt(encrypted);

    expect(decrypted.equals(plaintext)).toBe(true);
  });
});
