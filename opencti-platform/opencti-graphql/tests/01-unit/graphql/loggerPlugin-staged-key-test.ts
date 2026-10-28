import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    booleanConf: () => false,
    appLogExtendedErrors: true,
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

const STAGED_KEY = 'sync/inflight/sync--1/0123456789abcdef0123456789abcdef/content';

const buildImportPushRefContext = (graphQLError: unknown) => ({
  request: {
    variables: { id: 'report--1', fileRef: { sync_id: 'sync--1', storage_key: STAGED_KEY, name: 'report.pdf' } },
    query: 'mutation ImportPushRef($id: ID!, $fileRef: FileRefInput!) { stixDomainObjectEdit(id: $id) { importPushRef(fileRef: $fileRef) { id } } }',
  },
  operationName: 'ImportPushRef',
  operation: { operation: 'mutation' },
  contextValue: { user: { id: 'test-user' } },
  errors: [graphQLError],
});

describe('loggerPlugin - staged sync file key', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redacts the staged key from the variables logged with an extended error', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildImportPushRefContext(FunctionalError('Cannot copy referenced sync file', { syncId: 'sync--1' })));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(vi.mocked(logApp.warn).mock.calls)).not.toContain(STAGED_KEY);
  });

  it('redacts the staged key from the input published for a forbidden access', async () => {
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildImportPushRefContext(ForbiddenAccess()));

    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(vi.mocked(publishUserAction).mock.calls)).not.toContain(STAGED_KEY);
  });
});
