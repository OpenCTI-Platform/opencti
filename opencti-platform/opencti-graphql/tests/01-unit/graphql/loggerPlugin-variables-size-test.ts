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
import { logApp } from '../../../src/config/conf';
import { ForbiddenAccess, FunctionalError } from '../../../src/config/errors';
import { publishUserAction } from '../../../src/listener/UserActionListener';

// The size of the variables is only informative: when it cannot be computed, the request is still logged
const QUERY = 'query SizeQuery($input: Any) { anyField(input: $input) }';
const buildNestedValue = (depth: number) => {
  let value: unknown = 'v';
  for (let i = 0; i < depth; i += 1) value = { a: value };
  return value;
};
const buildRequestContext = (input: unknown, error: unknown) => ({
  request: { variables: { input }, query: QUERY },
  document: parse(QUERY),
  operationName: 'SizeQuery',
  operation: { operation: 'query' },
  contextValue: { user: { id: 'test-user' } },
  errors: [error],
});

describe('loggerPlugin - size of the variables', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should log the size of the variables', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext('v', FunctionalError('Functional')));
    expect(logApp.warn).toHaveBeenCalledWith('Functional', expect.objectContaining({ size: Buffer.byteLength('{"input":"v"}') }));
  });

  it('should log the request when the size of the variables cannot be computed', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(buildNestedValue(100_000), FunctionalError('Functional')));
    expect(logApp.warn).toHaveBeenCalledWith('Functional', expect.objectContaining({ size: -1 }));
  });

  it('should publish the forbidden access when the size of the variables cannot be computed', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(buildNestedValue(100_000), ForbiddenAccess()));
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({ event_scope: 'unauthorized' }));
  });
});
