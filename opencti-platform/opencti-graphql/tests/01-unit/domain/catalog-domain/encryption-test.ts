import { describe, expect, it } from 'vitest';
import { processPasswordConfigurationValue } from '../../../../src/modules/catalog/catalog-domain';

const TEST_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`;

describe('Encryption functions', () => {
  describe('processPasswordConfigurationValue', () => {
    it('should encrypt a simple password', () => {
      const password = 'mySecretPassword123';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      // Verify it's base64 encoded
      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();

      // Verify it's properly encrypted
      expect(encrypted).not.toBe(password);
      expect(encrypted.length).toBeGreaterThan(password.length);

      // Verify the structure is correct
      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01); // Version byte
      expect(buffer.length).toBeGreaterThan(256 + 1 + 16); // RSA key + version + min AES data
    });

    it('should encrypt an empty password', () => {
      const password = '';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(encrypted).not.toBe(password);

      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01);
      expect(buffer.length).toBeGreaterThan(256 + 1); // Still has RSA encrypted key even for empty string
    });

    it('should encrypt a very long password', () => {
      const password = 'a'.repeat(1000);
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(encrypted).not.toBe(password);

      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01);
      expect(buffer.length).toBeGreaterThan(1000); // Should be at least as long as original + overhead
    });

    it('should encrypt passwords with special characters', () => {
      const password = '!@#$%^&*()_+-=[]{}|;\':",./<>?`~€£¥';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(encrypted).not.toBe(password);

      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01);
    });

    it('should encrypt Unicode passwords', () => {
      const password = '密码🔐パスワード🔒';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(encrypted).not.toBe(password);

      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01);
    });

    it('should produce different encrypted values for the same password (due to random AES key)', () => {
      const password = 'testPassword';
      const encrypted1 = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);
      const encrypted2 = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      // Different encrypted values due to random AES key/IV
      expect(encrypted1).not.toBe(encrypted2);

      // Both should still be valid encrypted formats
      const buffer1 = Buffer.from(encrypted1, 'base64');
      const buffer2 = Buffer.from(encrypted2, 'base64');
      expect(buffer1[0]).toBe(0x01);
      expect(buffer2[0]).toBe(0x01);
    });

    it('should handle passwords with newlines and tabs', () => {
      const password = 'line1\nline2\ttabbed\r\nwindows';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
      expect(encrypted).not.toBe(password);

      const buffer = Buffer.from(encrypted, 'base64');
      expect(buffer[0]).toBe(0x01);
    });

    it('should throw error with invalid public key', () => {
      const password = 'testPassword';
      const invalidKey = 'not-a-valid-key';

      expect(() => {
        processPasswordConfigurationValue(password, invalidKey);
      }).toThrow();
    });

    it('should throw error with malformed public key', () => {
      const password = 'testPassword';
      const malformedKey = `-----BEGIN PUBLIC KEY-----
INVALID_BASE64_CONTENT!!!
-----END PUBLIC KEY-----`;

      expect(() => {
        processPasswordConfigurationValue(password, malformedKey);
      }).toThrow();
    });
  });

  describe('Encryption format validation', () => {
    it('should produce base64 output with correct structure', () => {
      const password = 'test';
      const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);

      // Check it's valid base64
      const buffer = Buffer.from(encrypted, 'base64');

      // Check version byte
      expect(buffer[0]).toBe(0x01);

      // Check minimum length (version + RSA encrypted key/IV + AES encrypted data + auth tag)
      expect(buffer.length).toBeGreaterThan(256 + 1 + 16); // RSA 2048 = 256 bytes, version = 1 byte, auth tag = 16 bytes
    });

    it('should maintain encryption format consistency', () => {
      const password = 'consistencyTest';

      // Multiple encryptions should all produce valid format
      for (let i = 0; i < 5; i += 1) {
        const encrypted = processPasswordConfigurationValue(password, TEST_RSA_PUBLIC_KEY);
        const buffer = Buffer.from(encrypted, 'base64');

        expect(buffer[0]).toBe(0x01); // Version byte
        expect(buffer.length).toBeGreaterThan(256 + 1 + 16); // Consistent minimum size
      }
    });
  });
});
