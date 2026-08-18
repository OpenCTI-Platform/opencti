/**
 * One mask for API tokens (#17758).
 *
 * The platform used to mask a token two different ways: logs printed the first 20
 * characters, the stored masked_token (which GraphQL and the UI read) printed the last 4.
 * The two share no characters, so an operator reading "Error resolving user by token"
 * could not tell which user it was about without decrypting the database.
 *
 * These tests pin the single mask and, separately, pin that the log line really goes
 * through it — the log path is the half of the bug that no test covered.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { generateSecureToken, maskToken } from '../../../../src/modules/user/user-domain';

// A legacy token (the UUID shape migrated by 1769815233918) and a current one.
const LEGACY_UUID_TOKEN = 'd434ce02-9d16-4f04-9c1b-91d4c46da5bd';
const CURRENT_TOKEN = 'flgrn_octi_tkn_hLQ8mS3vZpN1xR7bT0yK4cWgJ6dFaE9uP2iO5nQrX8sYbAtVzM1lC3hG7jD0kU';

describe('maskToken', () => {
  it('reveals the last 4 characters and nothing else', () => {
    expect(maskToken(LEGACY_UUID_TOKEN)).toBe('****a5bd');
    expect(maskToken(CURRENT_TOKEN)).toBe('****D0kU');
  });

  it('never leaks the front of the token — the regression #17758 is about', () => {
    // The old log mask was bearerToken.substring(0, 20). For a legacy UUID that is 20 of
    // its 36 characters in plaintext; for a current token it is the constant prefix plus
    // 5 characters of the random part. Neither may survive anywhere in the mask.
    for (const token of [LEGACY_UUID_TOKEN, CURRENT_TOKEN]) {
      const masked = maskToken(token);
      expect(masked).not.toContain(token.substring(0, 20));
      expect(masked).not.toContain('flgrn_octi_tkn_');
      // Everything but the trailing 4 characters is masked out.
      expect(masked.replace(/^\*{4}/, '')).toBe(token.slice(-4));
      expect(masked.length).toBe(8);
    }
  });

  it('echoes nothing when there is nothing worth masking', () => {
    // bearerToken comes straight off an untrusted Authorization header, so a caller can
    // choose a string shorter than the mask. Emit the mask, not the caller's string.
    expect(maskToken('')).toBe('****');
    expect(maskToken('abc')).toBe('****');
    expect(maskToken(undefined)).toBe('****');
    expect(maskToken(null)).toBe('****');
    expect(maskToken('abcd')).toBe('****abcd');
  });

  it('is byte-identical to the previous stored mask for every real token length', () => {
    // The stored masked_token was `****${token.slice(-4)}`. Changing what is written to
    // the database was not the point of #17758, so on real tokens this must be a no-op.
    for (const token of [LEGACY_UUID_TOKEN, CURRENT_TOKEN]) {
      expect(maskToken(token)).toBe(`****${token.slice(-4)}`);
    }
  });

  it('is the mask generateSecureToken hands to the database', async () => {
    const { token, masked_token } = await generateSecureToken();
    expect(masked_token).toBe(maskToken(token));
  });
});

// ─── The log path ────────────────────────────────────────────────────────────────
// Mocked separately because authenticateUserFromRequest pulls in the whole auth stack.

const logWarn = vi.fn();

vi.mock('../../../../src/config/conf', async () => {
  const actual: any = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { ...actual.logApp, warn: (...args: any[]) => logWarn(...args) },
  };
});

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntityFromCache: vi.fn().mockResolvedValue(null),
}));
vi.mock('../../../../src/database/engine', () => ({
  elLoadBy: vi.fn().mockResolvedValue(null),
  elRawDeleteByQuery: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../../src/database/redis', () => ({ notify: vi.fn() }));
vi.mock('../../../../src/database/redis/token_usage', () => ({
  getTokensUsage: vi.fn().mockResolvedValue([]),
  updateTokenUsage: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/domain/xtm-auth', () => ({ verifyXtmJwt: vi.fn(), isOwnIssuer: vi.fn() }));
// src/domain/user transitively reaches two packages with native bindings — the python
// bridge and re2, by way of src/parser/json-mapper. Neither is on the authentication path;
// they are stubbed so this stays a unit test.
vi.mock('../../../../src/python/pythonBridge', () => ({
  execChildPython: vi.fn(),
  checkPythonAvailability: vi.fn(),
  executePython: vi.fn(),
}));
vi.mock('re2', () => ({ default: RegExp }));

describe('the token that fails authentication is logged with that same mask', () => {
  beforeEach(() => {
    logWarn.mockClear();
  });

  const requestWith = (token: string) => ({
    headers: { authorization: `Bearer ${token}`, 'user-agent': 'vitest', origin: 'http://localhost' },
    session: undefined,
  });

  it('logs masked_token, matching what the profile page shows for that token', async () => {
    const { authenticateUserFromRequest } = await import('../../../../src/domain/user');
    const { testContext } = await import('../../../utils/testQuery');

    const result = await authenticateUserFromRequest(testContext, requestWith(LEGACY_UUID_TOKEN) as any);
    expect(result).toBeUndefined();

    const call = logWarn.mock.calls.find((c) => c[0] === 'Error resolving user by token');
    expect(call, 'the failed-token warning was not emitted').toBeDefined();
    const payload = call![1];

    // The whole point of #17758: this value is greppable against masked_token in the API.
    expect(payload.masked_token).toBe(maskToken(LEGACY_UUID_TOKEN));
    expect(payload.masked_token).toBe('****a5bd');

    // And the old, wider field is gone rather than merely joined by a new one.
    expect(payload).not.toHaveProperty('token_prefix');
    expect(JSON.stringify(payload)).not.toContain(LEGACY_UUID_TOKEN.substring(0, 20));
  });
});
