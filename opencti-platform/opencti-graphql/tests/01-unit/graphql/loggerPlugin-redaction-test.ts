import { beforeEach, describe, expect, it, vi } from 'vitest';
import { parse, type OperationDefinitionNode } from 'graphql';

// Extended error messages and the performance logger both write the call's
// variables and query text to the application log: credentials must never reach it.
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    booleanConf: () => true,
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
import { FunctionalError } from '../../../src/config/errors';

const SECRET = 'Clear-text-1!';
const OTP = '12345678';

const buildRequestContext = (query: string, variables: Record<string, unknown>, errors: unknown[] = []) => ({
  request: { variables, query },
  operationName: 'TestOperation',
  operation: parse(query).definitions[0] as OperationDefinitionNode,
  contextValue: { user: { id: 'test-user' } },
  errors,
});

const loggedMeta = (logger: typeof logApp.warn) => vi.mocked(logger).mock.calls[0][1] as Record<string, unknown>;

describe('loggerPlugin - credentials in logged GraphQL calls', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redacts an admin-set password sent as a single edit input, and drops the query text', async () => {
    const query = 'mutation TestOperation($id: ID!, $input: [EditInput]!) { userEdit(id: $id) { fieldPatch(input: $input) { id } } }';
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(query, { id: 'user-1', input: { key: 'password', value: SECRET } }, [FunctionalError('Invalid password')]));

    const meta = loggedMeta(logApp.warn);
    expect(meta.variables).toEqual({ id: 'user-1', input: { key: 'password', value: '** Redacted **' } });
    expect(meta.operation_query).toBeUndefined();
    expect(JSON.stringify(meta)).not.toContain(SECRET);
  });

  it('redacts the new and current passwords of a profile change, also when the call succeeds', async () => {
    const query = 'mutation TestOperation($input: [EditInput]!, $password: String) { meEdit(input: $input, password: $password) { id } }';
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(query, { input: [{ key: 'password', value: [SECRET] }], password: 'Current-1!' }));

    const meta = vi.mocked(logApp.info).mock.calls[0][1] as Record<string, unknown>;
    expect(meta.variables).toEqual({ input: [{ key: 'password', value: '** Redacted **' }], password: '** Redacted **' });
    expect(meta.operation_query).toBeUndefined();
    expect(JSON.stringify(meta)).not.toContain(SECRET);
    expect(JSON.stringify(meta)).not.toContain('Current-1!');
  });

  it('redacts the new password and the reset code of a forgot-password change', async () => {
    const query = 'mutation TestOperation($input: ChangePasswordInput!) { changePassword(input: $input) }';
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(query, { input: { transactionId: 'tx-1', otp: OTP, newPassword: SECRET } }, [FunctionalError('Invalid password')]));

    const meta = loggedMeta(logApp.warn);
    expect(meta.variables).toEqual({ input: { transactionId: 'tx-1', otp: '** Redacted **', newPassword: '** Redacted **' } });
    expect(JSON.stringify(meta)).not.toContain(SECRET);
    expect(JSON.stringify(meta)).not.toContain(OTP);
  });

  it('keeps the query text of a mutation that carries no credential', async () => {
    const query = 'mutation TestOperation($input: ReportAddInput!) { reportAdd(input: $input) { id } }';
    const listener = loggerPlugin.requestDidStart();
    await listener.willSendResponse(buildRequestContext(query, { input: { name: 'report' } }, [FunctionalError('Invalid report')]));

    expect(loggedMeta(logApp.warn).operation_query).toBeDefined();
  });
});
