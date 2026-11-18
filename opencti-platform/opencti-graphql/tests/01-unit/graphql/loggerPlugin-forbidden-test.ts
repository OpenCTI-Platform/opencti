import { beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'graphql';

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
import { REDACTED_INFORMATION } from '../../../src/database/utils';

// The access to a disabled feature is refused before any authentication check: the call can come without a user
// Apollo sets the parsed document once the request is parsed: without it, every variable value is redacted
const FLAGGED_QUERY = 'query FlaggedQuery { flagged }';
const buildRequestContext = (user: unknown, parsed = true) => ({
  request: { variables: { id: 'id' }, query: FLAGGED_QUERY },
  document: parsed ? parse(FLAGGED_QUERY) : undefined,
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

  it('should redact every variable value of a request without a parsed document', async () => {
    const user = { id: 'test-user' };
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(user, false));
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      context_data: { operation: 'FlaggedQuery', input: { id: REDACTED_INFORMATION } },
    }));
  });

  it('should publish nothing for a call without a user', async () => {
    const listener = loggerPlugin.requestDidStart();
    await expect(listener.willSendResponse(buildRequestContext(undefined))).resolves.toBeUndefined();
    expect(publishUserAction).not.toHaveBeenCalled();
  });
});
