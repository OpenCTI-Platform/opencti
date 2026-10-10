import { beforeEach, describe, expect, it, vi } from 'vitest';
// Registers all entity/relation modules so the filter keys of the schema are known
// without requiring a live DB/ES stack.
import { registerModules } from '../../../src/composition-root';

// loggerPlugin.js decides the log severity of a GraphQL error from its extensions.code.
// We mock its side-effecting dependencies only.
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
import { UnsupportedError } from '../../../src/config/errors';
import { checkFiltersValidity } from '../../../src/utils/filtering/filtering-utils';
import type { FilterGroup } from '../../../src/generated/graphql';

registerModules();

const buildRequestContext = (graphQLError: unknown) => ({
  request: { variables: {}, query: 'query {}' },
  operationName: 'ListSDOs',
  operation: { operation: 'query' },
  contextValue: { user: { id: 'test-user' } },
  errors: [graphQLError],
});

const catchError = (fn: () => void) => {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('Expected the function to throw');
};

describe('loggerPlugin - severity of an incorrect filter keys failure', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it.each([
    { title: 'unknown key', key: 'labels' },
    { title: 'key with invalid characters', key: "name.']; ctx._source.value = true; //" },
  ])('should log a $title as info, not as error', async ({ key }) => {
    const filterGroup = { mode: 'and', filters: [{ key: [key], values: ['x'] }], filterGroups: [] } as FilterGroup;
    const graphQLError = catchError(() => checkFiltersValidity(filterGroup));

    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(graphQLError));

    expect(logApp.info).toHaveBeenCalledTimes(1);
    expect(logApp.error).not.toHaveBeenCalled();
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('should keep logging any other UnsupportedError as error', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(UnsupportedError('Playbook multiple entrypoint is not supported')));

    expect(logApp.error).toHaveBeenCalledTimes(1);
    expect(logApp.info).not.toHaveBeenCalled();
  });
});
