import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AbortError } from 'node-fetch';

// loggerPlugin.js decides the log severity of a GraphQL error based on
// whether its extensions.code is listed in FUNCTIONAL_ERRORS (-> warn)
// or not (-> error). We mock its side-effecting dependencies only.
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
import { DatabaseError } from '../../../src/config/errors';
import { wrapEngineError } from '../../../src/database/engine';

const buildRequestContext = (graphQLError: unknown) => ({
  request: { variables: {}, query: 'query {}' },
  operationName: 'TestOperation',
  operation: { operation: 'query' },
  contextValue: { user: { id: 'test-user' } },
  errors: [graphQLError],
});

describe('loggerPlugin - severity of an abort-before-ES-call failure', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('a genuine DatabaseError is still logged via logApp.error, regardless of its cause', async () => {
    // DATABASE_ERROR is a TECHNICAL_ERROR and stays logged at `error` level,
    // this is unrelated to the abort classification and must remain true.
    const abortCause = new AbortError('The http call was aborted before el request started.');
    const graphQLError = DatabaseError('Fail to execute engine pagination', { cause: abortCause });

    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(graphQLError));

    expect(logApp.error).toHaveBeenCalledTimes(1);
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('a search aborted before reaching Elasticsearch (via wrapEngineError, as used by elFindByIds/elPaginate) is logged via logApp.warn, not logApp.error', async () => {
    const abortCause = new AbortError('The http call was aborted before el request started.');
    const graphQLError = wrapEngineError('Fail to execute engine pagination', abortCause);

    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(graphQLError));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(logApp.error).not.toHaveBeenCalled();
  });
});
