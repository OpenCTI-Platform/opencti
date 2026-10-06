import { beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'graphql';

// With metrics on, an unnamed operation has its request text logged: credentials must never reach it.
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } };
});

vi.mock('../../../src/config/tracing', () => ({
  meterManager: { request: vi.fn(), error: vi.fn(), latency: vi.fn() },
}));

import telemetryPlugin from '../../../src/graphql/telemetryPlugin';
import { logApp } from '../../../src/config/conf';

const SECRET = 'Clear-text-1!';

const buildSendContext = (query: string, { parsed = true } = {}) => ({
  request: { query },
  operationName: undefined,
  document: parsed ? parse(query) : undefined,
  operation: undefined,
  contextValue: { req: { header: () => 'test-agent' } },
  errors: [],
});

const loggedQuery = () => (vi.mocked(logApp.info).mock.calls[0][1] as { query: string }).query;

describe('telemetryPlugin - unnamed operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('logs the text of an unnamed operation that carries no credential', async () => {
    const listener = telemetryPlugin.requestDidStart();
    await listener.willSendResponse(buildSendContext('query { me { id } }'));
    expect(loggedQuery()).toContain('me');
  });

  it('keeps the text of an unnamed credential operation out of the log', async () => {
    const listener = telemetryPlugin.requestDidStart();
    await listener.willSendResponse(buildSendContext(`mutation { meEdit(input: [{ key: "password", value: ["${SECRET}"] }]) { id } }`));
    expect(loggedQuery()).toBe('** Redacted **');
  });

  it('keeps the text of a request that cannot be classified out of the log', async () => {
    const listener = telemetryPlugin.requestDidStart();
    await listener.willSendResponse(buildSendContext(`mutation { meEdit(password: "${SECRET}"`, { parsed: false }));
    expect(loggedQuery()).toBe('** Redacted **');
  });
});
