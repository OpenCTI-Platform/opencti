import { beforeEach, describe, expect, it, vi } from 'vitest';

const TWELVE_HOURS = 12 * 60 * 60 * 1000;
// The maximum lifetime is read from the configuration, which is loaded with the first import
vi.hoisted(() => {
  process.env.APP__SESSION_MAX_LIFETIME = String(12 * 60 * 60 * 1000);
});

const { mockEndSessionByRawId, mockPublishUserAction } = vi.hoisted(() => ({
  mockEndSessionByRawId: vi.fn(),
  mockPublishUserAction: vi.fn(),
}));

// The session read by the subscription is the one already set on the request
vi.mock('../../../src/database/session', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/session')>()),
  getSessionMiddleware: vi.fn(async () => (_req: unknown, _res: unknown, next: () => void) => next()),
  endSessionByRawId: mockEndSessionByRawId,
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: mockPublishUserAction,
}));

vi.mock('../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/user/user-domain')>()),
  resolveSessionUser: vi.fn(),
}));

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  computeLoaders: vi.fn().mockReturnValue({}),
}));

// Only needed to create the server, not to read the session of a subscription
vi.mock('../../../src/graphql/graphql', () => ({ default: vi.fn(), createSubscriptionServerOptions: vi.fn() }));
vi.mock('../../../src/http/httpPlatform', () => ({ default: vi.fn() }));
vi.mock('../../../src/http/httpGraphqlContext', () => ({ createGraphqlContext: vi.fn() }));

import { extractWsSessionContext } from '../../../src/http/httpServer';
import { resolveSessionUser } from '../../../src/modules/user/user-domain';
import type { AuthUser } from '../../../src/types/user';

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(resolveSessionUser).mockReset();
});

describe('extractWsSessionContext: user of the session', () => {
  // A session logged in a minute ago, well under its maximum lifetime
  const sessionCreation = () => new Date(Date.now() - 60 * 1000).toISOString();
  const buildWsContext = (sessionUser: unknown) => {
    const session = { user: sessionUser, regenerate: vi.fn() };
    const context = { extra: { request: { session }, socket: { _socket: { remoteAddress: '::1' } } } };
    return { context, session };
  };

  it('builds the subscription context with the user resolved from the session', async () => {
    const sessionUser = { id: 'user-id', otp_validated: true, session_creation: sessionCreation() };
    const resolvedUser = { ...sessionUser, name: 'User', capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser;
    vi.mocked(resolveSessionUser).mockResolvedValue(resolvedUser);
    const { context, session } = buildWsContext(sessionUser);
    const sessionContext = await extractWsSessionContext(context);
    expect(resolveSessionUser).toHaveBeenCalledWith(expect.anything(), session, sessionUser);
    expect(sessionContext.user?.name).toBe('User');
    expect(sessionContext.user?.origin).toMatchObject({ socket: 'subscription', ip: '::1', user_id: 'user-id' });
    expect(sessionContext.batch).toBeDefined();
  });

  it('refuses a subscription whose session user cannot be resolved', async () => {
    vi.mocked(resolveSessionUser).mockResolvedValue(undefined);
    const { context } = buildWsContext({ id: 'unknown-user-id', session_creation: sessionCreation() });
    await expect(extractWsSessionContext(context)).rejects.toThrow('User must be authenticated');
    expect(resolveSessionUser).toHaveBeenCalledTimes(1);
  });

  it('refuses a subscription without a session user', async () => {
    const { context } = buildWsContext(undefined);
    await expect(extractWsSessionContext(context)).rejects.toThrow('User must be authenticated');
    expect(resolveSessionUser).not.toHaveBeenCalled();
  });
});

describe('extractWsSessionContext: maximum lifetime of a session', () => {
  const USER = { id: 'user-1', internal_id: 'user-1', name: 'User 1', groups: [], organizations: [] };

  const subscriptionContext = (loginTime: number) => ({
    extra: {
      request: {
        sessionID: 'session-id',
        session: { user: { id: USER.id, session_creation: new Date(loginTime).toISOString() } },
      },
      socket: { _socket: { remoteAddress: '127.0.0.1' } },
    },
  });

  it('should accept a subscription of a session under its maximum lifetime', async () => {
    vi.mocked(resolveSessionUser).mockResolvedValue(USER as unknown as AuthUser);
    const context = subscriptionContext(Date.now() - TWELVE_HOURS + 60 * 1000);
    const sessionContext = await extractWsSessionContext(context);
    expect(sessionContext.user?.id).toEqual(USER.id);
  });

  it('should refuse a subscription of a session over its maximum lifetime, without ending the session', async () => {
    const context = subscriptionContext(Date.now() - TWELVE_HOURS - 60 * 1000);
    await expect(extractWsSessionContext(context)).rejects.toThrow('User must be authenticated');
    // The logout of a subscription is ignored by the activity listener: the next HTTP request ends the session
    expect(mockEndSessionByRawId).not.toHaveBeenCalled();
    expect(mockPublishUserAction).not.toHaveBeenCalled();
    expect(context.extra.request.session).toBeDefined();
    // Refused before the user of the session is resolved (no users cache or database lookup)
    expect(resolveSessionUser).not.toHaveBeenCalled();
  });
});
