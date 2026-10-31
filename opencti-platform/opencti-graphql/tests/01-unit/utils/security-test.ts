import { describe, it, expect } from 'vitest';
import { buildTokenAuthFailureLogMeta, generateSecureToken, maskToken, TOKEN_MASK } from '../../../src/modules/user/user-domain';

describe('Utils > Security', () => {
  it('should generate a secure token with correct format', async () => {
    const { token, hash, masked_token } = await generateSecureToken();

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
    expect(hash.length).toBe(44);

    // Check masked token
    expect(masked_token.startsWith('****')).toBe(true);
    expect(masked_token.endsWith(token.slice(-4))).toBe(true);
    expect(masked_token.length).toBe(8); // **** + 4 chars
    expect(masked_token).toBe(maskToken(token));
  });

  it('should mask a token as **** plus its last 4 characters', () => {
    expect(maskToken('flgrn_octi_tkn_abcdefghijklmnopWXYZ')).toBe('****WXYZ');
    expect(maskToken('d434ce02-e58e-4cac-8b4c-42bf16748e84')).toBe('****8e84');
  });

  it('should never reveal any character of a short or missing token', () => {
    expect(maskToken('abcdefghijk')).toBe(TOKEN_MASK);
    expect(maskToken('')).toBe(TOKEN_MASK);
    expect(maskToken(null)).toBe(TOKEN_MASK);
    expect(maskToken(undefined)).toBe(TOKEN_MASK);
  });

  it('should log a failed token authentication with the masked token only', () => {
    const token = 'flgrn_octi_tkn_0123456789abcdefghijklmnopqrstuvwxyz9876';
    const cause = new Error('invalid token');
    const meta = buildTokenAuthFailureLogMeta(cause, token, {
      headers: { 'user-agent': 'pycti/7', origin: 'https://opencti.example' },
    });
    expect(meta).toEqual({
      cause,
      masked_token: '****9876',
      user_agent: 'pycti/7',
      origin: 'https://opencti.example',
    });
    expect(meta).not.toHaveProperty('token_prefix');
    // No prefix of the live token anywhere in the log metadata
    expect(JSON.stringify(meta)).not.toContain(token.substring(0, 8));
  });

  it('should default user agent and origin in the token failure log', () => {
    const meta = buildTokenAuthFailureLogMeta(undefined, 'flgrn_octi_tkn_0123456789abcdef', {
      headers: { referer: 'https://opencti.example/dashboard' },
    });
    expect(meta.masked_token).toBe('****cdef');
    expect(meta.user_agent).toBe('unknown');
    expect(meta.origin).toBe('https://opencti.example/dashboard');
  });
});
