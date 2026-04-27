/**
 * Security unit tests — api_token removal (PR #15686)
 *
 * Two categories:
 *  - Pure unit tests (0 mock): sanitizeUser schema, never exposes api_token in templates
 *  - DB unit tests (minimal mocks): addUser never persists api_token
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

// ─── DB / External mocks (only what cannot run without infrastructure) ────────

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn().mockResolvedValue({}),
  patchAttribute: vi.fn().mockResolvedValue({ element: {} }),
  updateAttribute: vi.fn().mockResolvedValue({ element: {} }),
  deleteRelationsByFromAndTo: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/database/engine', () => ({
  elLoadBy: vi.fn().mockResolvedValue(null),
  elRawDeleteByQuery: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
  getEntityFromCache: vi.fn().mockResolvedValue({ platform_organization: null, platform_session_max_concurrent: 0 }),
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/domain/group', () => ({
  findGroupPaginated: vi.fn().mockResolvedValue({ edges: [] }),
  defaultMarkingDefinitionsFromGroups: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/database/session', () => ({
  findUserSessions: vi.fn().mockResolvedValue([]),
  killSessions: vi.fn().mockResolvedValue({}),
}));

vi.mock('passport', () => ({
  default: {
    authenticate: vi.fn(),
    _strategy: vi.fn().mockReturnValue({ logger: null }),
  },
}));

vi.mock('../../../src/modules/authenticationProvider/providers-configuration', () => ({
  PROVIDERS: [],
  LOCAL_STRATEGY_IDENTIFIER: 'local',
  isLocalAuthForcedEnabledFromEnv: vi.fn().mockReturnValue(true),
  getConfigurationAdminEmail: vi.fn(),
  getConfigurationAdminPassword: vi.fn(),
  getConfigurationAdminToken: vi.fn(),
}));

vi.mock('../../../src/domain/settings', () => ({
  getSettings: vi.fn().mockResolvedValue({ local_auth: { enabled: true }, platform_organization: null, platform_session_max_concurrent: 0 }),
}));

// ─── Imports (must come after vi.mock) ───────────────────────────────────────

import passport from 'passport';
import { addUser, sessionLogin } from '../../../src/domain/user';
import { createEntity } from '../../../src/database/middleware';
import { getEntitiesMapFromCache } from '../../../src/database/cache';
import { SYSTEM_USER } from '../../../src/utils/access';
import { sanitizeUser } from '../../../src/utils/templateContextSanitizer';

// ─────────────────────────────────────────────────────────────────────────────
// Pure unit tests — zero mocks, zero setup
// ─────────────────────────────────────────────────────────────────────────────

describe('sanitizeUser — api_token must never appear in template context', () => {
  it('removes api_token from a user that has one', () => {
    const user = {
      name: 'Admin',
      user_email: 'admin@opencti.io',
      user_name: 'admin',
      account_status: 'Active',
      api_token: 'plaintext-secret-that-must-not-leak',
    };

    const result = sanitizeUser(user);

    expect(result).not.toHaveProperty('api_token');
  });

  it('preserves the safe user fields after sanitization', () => {
    const user = {
      name: 'Alice',
      firstname: 'Alice',
      lastname: 'Smith',
      user_email: 'alice@example.com',
      user_name: 'alice',
      account_status: 'Active',
      api_token: 'should-be-stripped',
    };

    const result = sanitizeUser(user);

    expect(result.name).toBe('Alice');
    expect(result.firstname).toBe('Alice');
    expect(result.lastname).toBe('Smith');
    expect(result.user_email).toBe('alice@example.com');
    expect(result.account_status).toBe('Active');
    expect(result).not.toHaveProperty('api_token');
  });

  it('handles a user object that has no api_token', () => {
    const user = { name: 'Bob', user_email: 'bob@example.com', user_name: 'bob', account_status: 'Active' };

    const result = sanitizeUser(user);

    expect(result).toStrictEqual(user);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// DB unit tests — only the DB layer is mocked
// ─────────────────────────────────────────────────────────────────────────────

describe('addUser — api_token must never be persisted', () => {
  const context = {} as any;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createEntity).mockResolvedValue({
      element: { id: 'new-user-id', user_email: 'test@example.com' },
      isCreation: true,
    } as any);
  });

  it('does not write api_token to the database even if it is in the input', async () => {
    await addUser(context, SYSTEM_USER, {
      user_email: 'test@example.com',
      name: 'Test',
      external: true,
      api_token: 'plaintext-legacy-token',
    });

    const [, , persistedEntity] = vi.mocked(createEntity).mock.calls[0];
    expect(persistedEntity).not.toHaveProperty('api_token');
  });

  it('preserves legitimate fields while stripping api_token', async () => {
    await addUser(context, SYSTEM_USER, {
      user_email: 'alice@example.com',
      name: 'Alice',
      language: 'fr',
      external: true,
      api_token: 'strip-me',
    });

    const [, , persistedEntity] = vi.mocked(createEntity).mock.calls[0];
    expect(persistedEntity).toHaveProperty('user_email', 'alice@example.com');
    expect(persistedEntity).toHaveProperty('language', 'fr');
    expect(persistedEntity).not.toHaveProperty('api_token');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Session unit tests — login mutation must not expose the token
// ─────────────────────────────────────────────────────────────────────────────

describe('sessionLogin — must return null, not the session token', () => {
  const context = {
    req: {
      ip: '127.0.0.1',
      headers: {},
      header: () => undefined,
      socket: { remoteAddress: '127.0.0.1' },
      session: { user: null as any, session_provider: null as any, save: vi.fn() },
    },
  } as any;

  const cachedUser = {
    id: 'user-id',
    internal_id: 'user-id',
    standard_id: 'user--user-id',
    entity_type: 'User',
    account_status: 'Active',
    groups: [],
    organizations: [],
    headers_audit: [],
    user_service_account: false,
    account_lock_after_date: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    context.req.session.save = vi.fn();
    context.req.session.user = null;
  });

  it('returns null on successful login — the token is never exposed', async () => {
    vi.mocked(passport.authenticate as any).mockImplementation(
      (_s: string, _o: unknown, cb: (_e: unknown, _u: unknown, _i: unknown) => void) => () => cb(null, cachedUser, null),
    );
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(
      new Map([[cachedUser.internal_id, cachedUser]]) as any,
    );

    const result = await sessionLogin(context, { email: 'user@example.com', password: 'pass' });

    expect(result).toBeNull();
  });

  it('creates a server-side session even though the response is null', async () => {
    vi.mocked(passport.authenticate as any).mockImplementation(
      (_s: string, _o: unknown, cb: (_e: unknown, _u: unknown, _i: unknown) => void) => () => cb(null, cachedUser, null),
    );
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(
      new Map([[cachedUser.internal_id, cachedUser]]) as any,
    );

    await sessionLogin(context, { email: 'user@example.com', password: 'pass' });

    expect(context.req.session.save).toHaveBeenCalled();
    expect(context.req.session.user).not.toBeNull();
  });

  it('throws when credentials are invalid', async () => {
    vi.mocked(passport.authenticate as any).mockImplementation(
      (_s: string, _o: unknown, cb: (_e: unknown, _u: unknown, _i: unknown) => void) => () => cb(null, null, null),
    );

    await expect(
      sessionLogin(context, { email: 'wrong@example.com', password: 'bad' }),
    ).rejects.toThrow();
  });
});
