import { beforeEach, describe, expect, it, vi } from 'vitest';
import { GraphQLError } from 'graphql';

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

interface TestRequest {
  query: string;
  variables: Record<string, unknown>;
}

interface TestFileRef {
  sync_id: string;
  storage_key: string;
  name: string;
}

const buildFileRef = (): TestFileRef => ({ sync_id: 'sync--1', storage_key: STAGED_KEY, name: 'report.pdf' });

const importPushRefRequest = (): TestRequest => ({
  query: 'mutation ImportPushRef($id: ID!, $fileRef: FileRefInput!) { stixDomainObjectEdit(id: $id) { importPushRef(fileRef: $fileRef) { id } } }',
  variables: { id: 'report--1', fileRef: buildFileRef() },
});
const renamedVariableRequest = (): TestRequest => ({
  query: 'mutation ImportPushRef($id: ID!, $ref: FileRefInput!) { stixDomainObjectEdit(id: $id) { importPushRef(fileRef: $ref) { id } } }',
  variables: { id: 'report--1', ref: buildFileRef() },
});
const splitVariablesRequest = (): TestRequest => ({
  query: 'mutation ImportPushRef($id: ID!, $k: String!) { stixDomainObjectEdit(id: $id) { importPushRef(fileRef: { sync_id: "sync--1", storage_key: $k, name: "report.pdf" }) { id } } }',
  variables: { id: 'report--1', k: STAGED_KEY },
});
const inlineKeyRequest = (): TestRequest => ({
  query: `mutation ImportPushRef { stixDomainObjectEdit(id: "report--1") { importPushRef(fileRef: { sync_id: "sync--1", storage_key: "${STAGED_KEY}", name: "report.pdf" }) { id } } }`,
  variables: {},
});

const buildContext = (request: TestRequest, graphQLError: unknown) => ({
  request,
  source: request.query,
  operationName: 'ImportPushRef',
  operation: { operation: 'mutation' },
  contextValue: { user: { id: 'test-user' } },
  errors: [graphQLError],
});

const sendResponse = async (request: TestRequest, graphQLError: unknown) => {
  const listener = loggerPlugin.requestDidStart();
  await listener.willSendResponse(buildContext(request, graphQLError));
};

const warnLogs = (): string => JSON.stringify(vi.mocked(logApp.warn).mock.calls);

describe('loggerPlugin - staged sync file key', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redacts the staged key from the variables logged with an extended error', async () => {
    await sendResponse(importPushRefRequest(), FunctionalError('Cannot copy referenced sync file', { syncId: 'sync--1' }));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).not.toContain(STAGED_KEY);
    expect(warnLogs()).toContain('Cannot copy referenced sync file');
  });

  it('redacts the staged key from the input published for a forbidden access', async () => {
    await sendResponse(importPushRefRequest(), ForbiddenAccess());

    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(vi.mocked(publishUserAction).mock.calls)).not.toContain(STAGED_KEY);
  });

  it('redacts the staged key whatever the variable name', async () => {
    await sendResponse(renamedVariableRequest(), FunctionalError('Cannot copy referenced sync file', { syncId: 'sync--1' }));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).not.toContain(STAGED_KEY);
  });

  it('redacts the staged key passed as its own variable', async () => {
    await sendResponse(splitVariablesRequest(), FunctionalError('Cannot copy referenced sync file', { syncId: 'sync--1' }));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).not.toContain(STAGED_KEY);
  });

  it('redacts the staged key written inline in the query', async () => {
    await sendResponse(inlineKeyRequest(), FunctionalError('Cannot copy referenced sync file', { syncId: 'sync--1' }));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).not.toContain(STAGED_KEY);
  });

  it('redacts the staged key echoed by a variable coercion error', async () => {
    const coercionError = new GraphQLError(`Variable "$fileRef" has invalid value: found: { storage_key: "${STAGED_KEY}" }.`, { extensions: { code: 'BAD_USER_INPUT' } });
    await sendResponse(importPushRefRequest(), coercionError);

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).not.toContain(STAGED_KEY);
  });

  it('keeps the variables of other operations in the extended error log', async () => {
    const otherRequest: TestRequest = { query: 'mutation ReportEdit($id: ID!) { reportEdit(id: $id) { id } }', variables: { id: 'report--1' } };
    await sendResponse(otherRequest, FunctionalError('Report edit failed'));

    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(warnLogs()).toContain('report--1');
  });
});
