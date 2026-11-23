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

vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  computeLoaders: vi.fn().mockReturnValue({}),
}));

// Only needed to create the server, not to read the session of a subscription
vi.mock('../../../src/graphql/graphql', () => ({ default: vi.fn(), createSubscriptionServerOptions: vi.fn() }));
vi.mock('../../../src/http/httpPlatform', () => ({ default: vi.fn() }));
vi.mock('../../../src/http/httpGraphqlContext', () => ({ createGraphqlContext: vi.fn() }));

import { extractWsSessionContext } from '../../../src/http/httpServer';
import { getEntitiesMapFromCache } from '../../../src/database/cache';

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

describe('extractWsSessionContext: maximum lifetime of a session', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([[USER.id, USER]]) as any);
  });

  it('should accept a subscription of a session under its maximum lifetime', async () => {
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
  });
});
