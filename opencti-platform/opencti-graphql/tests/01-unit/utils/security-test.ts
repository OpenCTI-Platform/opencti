import { describe, it, expect } from 'vitest';
import { generateSecureToken } from '../../../src/utils/security';

describe('Utils > Security', () => {
  it('should generate a secure token with correct format', () => {
    const { token, hash, masked_token } = generateSecureToken();

    // Check token format
    expect(token.startsWith('flgrn_octi_tkn_')).toBe(true);
    // Prefix length is 15. Random part is 64 chars (48 bytes base64url).
    // Total length = 15 + 64 = 79.
    // Wait, let's verify exact length expectation.
    // 48 bytes -> base64 is 64 chars.
    // Prefix 'flgrn_octi_tkn_' is 15 chars.
    expect(token.length).toBe(15 + 64);

    // Check hash
    expect(hash).toBeDefined();
    expect(hash.length).toBe(64); // SHA-256 hex is 64 chars

    // Check masked token
    expect(masked_token.startsWith('****')).toBe(true);
    expect(masked_token.endsWith(token.slice(-4))).toBe(true);
    expect(masked_token.length).toBe(8); // **** + 4 chars
  });
});
