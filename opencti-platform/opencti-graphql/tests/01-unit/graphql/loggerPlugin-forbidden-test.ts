import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    booleanConf: () => false,
    appLogExtendedErrors: false,
  };
});

vi.mock('../../../src/domain/settings', () => ({
  getMemoryStatistics: vi.fn(() => ({})),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

import loggerPlugin from '../../../src/graphql/loggerPlugin';
import { ForbiddenAccess } from '../../../src/config/errors';
import { publishUserAction } from '../../../src/listener/UserActionListener';

// The access to a disabled feature is refused before any authentication check: the call can come without a user
const buildRequestContext = (user: unknown) => ({
  request: { variables: { id: 'id' }, query: 'query FlaggedQuery { flagged }' },
  operationName: 'FlaggedQuery',
  operation: { operation: 'query' },
  contextValue: { user },
  errors: [ForbiddenAccess('Feature is disabled', { flags: ['SOME_FLAG'] })],
});

describe('loggerPlugin - forbidden access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should publish the unauthorized access of a user', async () => {
    const user = { id: 'test-user' };
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(user));
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith({
      user,
      event_type: 'read',
      event_scope: 'unauthorized',
      event_access: 'administration',
      status: 'error',
      context_data: { operation: 'FlaggedQuery', input: { id: 'id' } },
    });
  });

  it('should publish nothing for a call without a user', async () => {
    const listener = loggerPlugin.requestDidStart();
    await expect(listener.willSendResponse(buildRequestContext(undefined))).resolves.toBeUndefined();
    expect(publishUserAction).not.toHaveBeenCalled();
  });
});
