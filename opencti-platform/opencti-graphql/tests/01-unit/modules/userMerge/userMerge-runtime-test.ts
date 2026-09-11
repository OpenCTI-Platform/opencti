import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

interface RedisState {
  contextIds: string[];
  forgotPasswordId: string | undefined;
  sessions: Array<{ id: string }>;
  streamConnections: string[];
  usedTokenIds: string[];
}

const state: RedisState = { contextIds: [], forgotPasswordId: undefined, sessions: [], streamConnections: [], usedTokenIds: [] };
const updates: Array<{ id: string; inputs: unknown[] }> = [];
const deletedTokenIds: string[][] = [];
const deletedForgotPassword: string[] = [];
const notified: string[] = [];
const order: string[] = [];

vi.mock('../../../../src/database/middleware', () => ({
  updateAttribute: async (_context: unknown, _user: unknown, id: string, _type: string, inputs: unknown[]) => {
    order.push('revocation');
    updates.push({ id, inputs });
    return { element: {} };
  },
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: async (topic: string) => {
    order.push('notify');
    notified.push(topic);
  },
  fetchUserContextIds: async () => state.contextIds,
  delUserContext: async () => {
    const removed = state.contextIds;
    state.contextIds = [];
    return removed;
  },
  redisGetForgotPasswordOtpPointer: async () => ({ id: state.forgotPasswordId }),
  redisDelForgotPassword: async (id: string) => {
    deletedForgotPassword.push(id);
    state.forgotPasswordId = undefined;
  },
}));

vi.mock('../../../../src/database/redis/token_usage', () => ({
  delTokensUsage: async (tokenIds: string[]) => {
    order.push('usage-keys');
    deletedTokenIds.push(tokenIds);
    return tokenIds.length;
  },
  getTokensUsage: async (tokenIds: string[]) => Object.fromEntries(
    tokenIds.filter((tokenId) => state.usedTokenIds.includes(tokenId)).map((tokenId) => [tokenId, 'used']),
  ),
}));

vi.mock('../../../../src/database/session', () => ({
  findUserSessions: async () => state.sessions,
  killUserSessions: async () => {
    const killed = state.sessions;
    state.sessions = [];
    return killed;
  },
}));

vi.mock('../../../../src/graphql/sseMiddleware', () => ({
  userStreamConnections: () => state.streamConnections,
  closeUserStreamConnections: () => {
    const count = state.streamConnections.length;
    state.streamConnections = [];
    return count;
  },
}));

const { userMergeRuntimeHandler } = await import('../../../../src/modules/userMerge/userMerge-runtimeHandler');
const { USER_MERGE_REGISTER } = await import('../../../../src/modules/userMerge/userMerge-register');

const context = {} as AuthContext;

const sourceUser = (tokenIds: string[] = []) => ({
  id: 'source-id',
  internal_id: 'source-id',
  user_email: 'source@filigran.io',
  api_tokens: tokenIds.map((id) => ({ id, name: `token-${id}` })),
}) as unknown as AuthUser;

const handlerContext = (source: AuthUser) => ({
  context,
  sourceUser: source,
  targetUser: { id: 'target-id' } as unknown as AuthUser,
} as never);

const NO_PLAN = { handler: 'source-runtime-invalidation', changes: [], alerts: [] };

describe('userMerge runtime handler', () => {
  beforeEach(() => {
    state.contextIds = [];
    state.forgotPasswordId = undefined;
    state.sessions = [];
    state.streamConnections = [];
    state.usedTokenIds = [];
    updates.length = 0;
    deletedTokenIds.length = 0;
    deletedForgotPassword.length = 0;
    notified.length = 0;
    order.length = 0;
  });

  it('should only claim rows the register declares', () => {
    const rowIds = USER_MERGE_REGISTER.map((row) => row.id);
    userMergeRuntimeHandler.covers.forEach((claimed) => {
      expect(rowIds).toContain(claimed);
    });
  });

  it('should report every claimed row in its plan', async () => {
    const plan = await userMergeRuntimeHandler.compute(handlerContext(sourceUser()));
    const reported = plan.changes.map((change) => change.register_row_id);
    expect(reported.sort()).toEqual([...userMergeRuntimeHandler.covers].sort());
  });

  it('should count the accesses the source holds', async () => {
    state.contextIds = ['ctx-1', 'ctx-2'];
    state.forgotPasswordId = 'transaction-1';
    state.sessions = [{ id: 'sess-1' }];
    state.streamConnections = ['conn-1', 'conn-2', 'conn-3'];
    state.usedTokenIds = ['token-a', 'token-b'];
    const plan = await userMergeRuntimeHandler.compute(handlerContext(sourceUser(['token-a', 'token-b'])));
    const counts = Object.fromEntries(plan.changes.map((change) => [change.register_row_id, change.count]));
    expect(counts['user.api-tokens']).toEqual(2);
    expect(counts['api-token.usage-key']).toEqual(2);
    expect(counts['session.key']).toEqual(1);
    expect(counts['session.platform-sessions']).toEqual(1);
    expect(counts['edit-context.keys']).toEqual(2);
    expect(counts['password-reset.keys']).toEqual(1);
    expect(counts['client-connection.auth-context']).toEqual(3);
  });

  it('should not count a usage key for a token that was never used', async () => {
    state.usedTokenIds = ['token-a'];
    const plan = await userMergeRuntimeHandler.compute(handlerContext(sourceUser(['token-a', 'token-b'])));
    const usage = plan.changes.find((change) => change.register_row_id === 'api-token.usage-key');
    // The row is reported as exact, and a key only exists once the token has been used.
    expect(usage?.count).toEqual(1);
    expect(usage?.exact).toBe(true);
  });

  it('should report the acknowledged rows at zero, with the reason', async () => {
    const plan = await userMergeRuntimeHandler.compute(handlerContext(sourceUser()));
    const password = plan.changes.find((change) => change.register_row_id === 'user.password');
    expect(password?.count).toEqual(0);
    expect(password?.detail).toContain('kept');
  });

  it('should revoke every token in a single operation', async () => {
    await userMergeRuntimeHandler.apply(handlerContext(sourceUser(['token-a', 'token-b'])), NO_PLAN);
    expect(updates).toHaveLength(1);
    expect(updates[0].id).toEqual('source-id');
    // One input per token would make the removals overwrite each other and leave a live token.
    expect(updates[0].inputs).toHaveLength(1);
    expect(updates[0].inputs[0]).toMatchObject({ key: 'api_tokens', value: [{ id: 'token-a' }, { id: 'token-b' }] });
    expect(deletedTokenIds).toEqual([['token-a', 'token-b']]);
  });

  it('should notify the user cache of the revocation', async () => {
    await userMergeRuntimeHandler.apply(handlerContext(sourceUser(['token-a'])), NO_PLAN);
    // `updateAttribute` publishes nothing, and the cache is what the API resolves a token
    // against: without the notification the revoked tokens keep authenticating.
    expect(notified).toHaveLength(1);
  });

  it('should not notify when the source holds no token', async () => {
    await userMergeRuntimeHandler.apply(handlerContext(sourceUser()), NO_PLAN);
    expect(notified).toHaveLength(0);
  });

  it('should drop the usage keys before the tokens they are named from', async () => {
    await userMergeRuntimeHandler.apply(handlerContext(sourceUser(['token-a'])), NO_PLAN);
    // A run failing after the revocation could no longer name the keys, and they never expire.
    expect(order).toEqual(['usage-keys', 'revocation', 'notify']);
  });

  it('should close every runtime access', async () => {
    state.contextIds = ['ctx-1'];
    state.forgotPasswordId = 'transaction-1';
    state.sessions = [{ id: 'sess-1' }, { id: 'sess-2' }];
    state.streamConnections = ['conn-1'];
    const invalidated = await userMergeRuntimeHandler.apply(handlerContext(sourceUser(['token-a'])), NO_PLAN);
    // 1 token + 1 usage key + 2 sessions + 1 context + 1 reset + 1 connection
    expect(invalidated).toEqual(7);
    expect(state.sessions).toEqual([]);
    expect(state.contextIds).toEqual([]);
    expect(state.streamConnections).toEqual([]);
    expect(deletedForgotPassword).toEqual(['transaction-1']);
  });

  it('should leave nothing to do on a second run', async () => {
    const source = sourceUser(['token-a']);
    state.sessions = [{ id: 'sess-1' }];
    await userMergeRuntimeHandler.apply(handlerContext(source), NO_PLAN);
    updates.length = 0;
    deletedTokenIds.length = 0;
    // The source is reloaded between runs, so the second pass sees a user without tokens.
    const invalidated = await userMergeRuntimeHandler.apply(handlerContext(sourceUser()), NO_PLAN);
    expect(invalidated).toEqual(0);
    expect(updates).toHaveLength(0);
    expect(deletedTokenIds).toEqual([]);
  });

  it('should close the accesses even when nothing was planned', async () => {
    const plan = await userMergeRuntimeHandler.compute(handlerContext(sourceUser()));
    expect(plan.changes.every((change) => change.count === 0)).toBe(true);
    // A session opened between the two passes is exactly what has to be closed.
    state.sessions = [{ id: 'sess-late' }];
    const invalidated = await userMergeRuntimeHandler.apply(handlerContext(sourceUser()), NO_PLAN);
    expect(invalidated).toEqual(1);
    expect(state.sessions).toEqual([]);
  });
});
