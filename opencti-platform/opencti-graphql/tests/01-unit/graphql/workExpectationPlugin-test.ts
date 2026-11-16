import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } };
});

vi.mock('../../../src/domain/work', () => ({
  reportExpectation: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
}));

import workExpectationPlugin from '../../../src/graphql/workExpectationPlugin';
import { reportExpectation } from '../../../src/domain/work';
import { getEntitiesMapFromCache } from '../../../src/database/cache';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const WORK_ID = 'work-id';
const REPORTED_HEADER = 'opencti-expectation-reported';

const workerUser = { id: 'worker-id', capabilities: [{ name: 'CONNECTORAPI' }] } as AuthUser;
const applicantUser = { id: 'applicant-id', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as AuthUser;
const request = { headers: { 'opencti-applicant-id': applicantUser.id }, header: () => undefined } as unknown as AuthContext['req'];

interface TestRequest {
  context: Partial<AuthContext>;
  operation?: string;
  errors?: Error[];
}

interface TestOperation {
  operation: string;
}

interface TestHttp {
  headers: Map<string, string>;
}

interface TestResponse {
  http: TestHttp;
}

interface TestRequestContext {
  contextValue: Partial<AuthContext>;
  operation: TestOperation;
  errors?: Error[];
  response: TestResponse;
}

interface WillSendResponseListener {
  willSendResponse: (requestContext: TestRequestContext) => Promise<void>;
}

const buildRequestContext = (testRequest: TestRequest): TestRequestContext => ({
  contextValue: { workId: WORK_ID, reportExpectationRequested: true, req: request, ...testRequest.context },
  operation: { operation: testRequest.operation ?? 'mutation' },
  errors: testRequest.errors,
  response: { http: { headers: new Map<string, string>() } },
});

const runPlugin = async (requestContext: TestRequestContext) => {
  const listener = await workExpectationPlugin.requestDidStart!({} as never);
  await (listener as WillSendResponseListener).willSendResponse(requestContext);
  return requestContext.response.http.headers.get(REPORTED_HEADER);
};

describe('workExpectationPlugin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([[workerUser.id, workerUser]]) as never);
  });

  it('should report as the worker when the worker impersonates an applicant', async () => {
    const requestContext = buildRequestContext({ context: { user: applicantUser, real_authentication_id: workerUser.id } });
    const reported = await runPlugin(requestContext);
    expect(reported).toBe('true');
    expect(reportExpectation).toHaveBeenCalledTimes(1);
    const [reportContext, reportUser, workId, error] = vi.mocked(reportExpectation).mock.calls[0];
    expect(reportUser.id).toBe(workerUser.id);
    expect(reportUser.origin.applicant_id).toBeUndefined();
    expect((reportContext as AuthContext).user?.id).toBe(workerUser.id);
    expect(workId).toBe(WORK_ID);
    expect(error).toBeNull();
  });

  it('should report as the worker when it does not impersonate', async () => {
    const requestContext = buildRequestContext({ context: { user: workerUser, real_authentication_id: workerUser.id } });
    expect(await runPlugin(requestContext)).toBe('true');
    expect(vi.mocked(reportExpectation).mock.calls[0][1]).toBe(workerUser);
  });

  it('should not report for a user without the workEdit capabilities', async () => {
    const requestContext = buildRequestContext({ context: { user: applicantUser, real_authentication_id: applicantUser.id } });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });

  it('should not report when the header is not sent', async () => {
    const requestContext = buildRequestContext({ context: { user: workerUser, reportExpectationRequested: false } });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });

  it('should not report without a work id', async () => {
    const requestContext = buildRequestContext({ context: { user: workerUser, workId: undefined } });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });

  it('should not report a query', async () => {
    const requestContext = buildRequestContext({ context: { user: workerUser }, operation: 'query' });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });

  it('should not report a mutation that failed', async () => {
    const requestContext = buildRequestContext({ context: { user: workerUser }, errors: [new Error('create failed')] });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });

  it('should confirm a failed report, so it is attempted once like the worker call', async () => {
    vi.mocked(reportExpectation).mockRejectedValueOnce(new Error('elastic down'));
    const requestContext = buildRequestContext({ context: { user: workerUser } });
    expect(await runPlugin(requestContext)).toBe('true');
    expect(reportExpectation).toHaveBeenCalledTimes(1);
  });

  it('should not confirm when the worker user cannot be resolved, so the worker reports itself', async () => {
    vi.mocked(getEntitiesMapFromCache).mockRejectedValueOnce(new Error('cache down'));
    const requestContext = buildRequestContext({ context: { user: applicantUser, real_authentication_id: workerUser.id } });
    expect(await runPlugin(requestContext)).toBeUndefined();
    expect(reportExpectation).not.toHaveBeenCalled();
  });
});
