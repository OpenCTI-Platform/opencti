import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as UserDomain from '../../../src/modules/user/user-domain';
import { extractWsSessionContext } from '../../../src/http/httpServer';
import type { AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/redis'); // to prevent connection attempts
// The request already holds its session: the session middleware has nothing to do
vi.mock('../../../src/database/session', async () => {
  const actual = await vi.importActual('../../../src/database/session');
  return { ...actual, getSessionMiddleware: async () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
vi.mock('../../../src/modules/user/user-domain', async () => {
  const actual = await vi.importActual('../../../src/modules/user/user-domain');
  return { ...actual, resolveSessionUser: vi.fn() };
});

const buildWsContext = (sessionUser: unknown) => {
  const session = { user: sessionUser, destroy: vi.fn() };
  const context = { extra: { request: { session }, socket: { _socket: { remoteAddress: '::1' } } } };
  return { context, session };
};

describe('extractWsSessionContext', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('builds the subscription context with the user resolved from the session', async () => {
    const sessionUser = { id: 'user-id', otp_validated: true };
    const resolvedUser = { ...sessionUser, name: 'User', capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser;
    vi.mocked(UserDomain.resolveSessionUser).mockResolvedValue(resolvedUser);
    const { context, session } = buildWsContext(sessionUser);
    const sessionContext = await extractWsSessionContext(context);
    expect(UserDomain.resolveSessionUser).toHaveBeenCalledWith(expect.anything(), session, sessionUser);
    expect(sessionContext.user?.name).toBe('User');
    expect(sessionContext.user?.origin).toMatchObject({ socket: 'subscription', ip: '::1', user_id: 'user-id' });
    expect(sessionContext.batch).toBeDefined();
  });

  it('refuses a subscription whose session user cannot be resolved', async () => {
    vi.mocked(UserDomain.resolveSessionUser).mockResolvedValue(undefined);
    const { context } = buildWsContext({ id: 'unknown-user-id' });
    await expect(extractWsSessionContext(context)).rejects.toThrow('User must be authenticated');
  });

  it('refuses a subscription without a session user', async () => {
    const { context } = buildWsContext(undefined);
    await expect(extractWsSessionContext(context)).rejects.toThrow('User must be authenticated');
    expect(UserDomain.resolveSessionUser).not.toHaveBeenCalled();
  });
});
