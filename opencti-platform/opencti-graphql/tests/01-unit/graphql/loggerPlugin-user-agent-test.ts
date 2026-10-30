import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HeaderMap } from '@apollo/server';

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
import { logApp } from '../../../src/config/conf';

const buildRequestContext = (headers?: HeaderMap) => ({
  request: { variables: {}, query: 'query {}', http: headers ? { headers } : undefined },
  operationName: 'TestOperation',
  operation: { operation: 'query' },
  contextValue: { user: { id: 'test-user' } },
  errors: [new Error('boom')],
});

const loggedMetadata = () => vi.mocked(logApp.error).mock.calls[0][1] as Record<string, unknown>;

describe('loggerPlugin - user agent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should log the user agent of the GraphQL call', async () => {
    const headers = new HeaderMap([['user-agent', 'pycti/6.9.0 (my-connector)']]);
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(headers));
    expect(loggedMetadata()).toMatchObject({ user_id: 'test-user', user_agent: 'pycti/6.9.0 (my-connector)' });
  });

  it('should log no user agent when the call sends none', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(new HeaderMap()));
    expect(loggedMetadata().user_agent).toBeUndefined();
  });

  it('should log no user agent when the call has no http request', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext());
    expect(loggedMetadata().user_agent).toBeUndefined();
  });
});
