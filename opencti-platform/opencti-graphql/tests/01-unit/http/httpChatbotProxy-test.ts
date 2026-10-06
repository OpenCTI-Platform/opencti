import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks ──────────────────────────────────────────────────────────────────

// nconf must be mocked before conf.js is ever loaded (transitively)
vi.mock('nconf', () => {
  const store: Record<string, unknown> = {
    'xtm:xtm_one_url': 'http://xtm-one',
  };
  return {
    default: {
      env: vi.fn().mockReturnThis(),
      add: vi.fn().mockReturnThis(),
      file: vi.fn().mockReturnThis(),
      defaults: vi.fn().mockReturnThis(),
      get: vi.fn((key: string) => store[key]),
      set: vi.fn(),
      path: vi.fn(() => []),
    },
  };
});

// Mock conf without importOriginal to avoid triggering conf.js initialization
vi.mock('../../../src/config/conf', () => ({
  default: {
    get: vi.fn((key: string) => {
      const store: Record<string, unknown> = {
        'xtm:xtm_one_url': 'http://xtm-one',
        'redis:use_ssl': false,
        'redis:ca': [],
        'playbook_manager:log_max_size': 100,
      };
      return store[key] ?? undefined;
    }),
  },
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  getChatbotUrl: vi.fn(() => 'http://localhost:4000'),
  PLATFORM_VERSION: '6.0.0',
  basePath: '',
  DEV_MODE: false,
  TEST_MODE: false,
  ENABLED_UI: false,
  OPENCTI_SESSION: 'opencti_session',
  AUTH_PAYLOAD_BODY_SIZE: undefined,
  getBaseUrl: vi.fn(() => 'http://localhost:4000'),
  getPlatformHttpProxyAgent: vi.fn(() => null),
  booleanConf: vi.fn(() => false),
  loadCert: vi.fn(() => ''),
}));

// Mock heavy I/O modules that get pulled in transitively. vi.hoisted is
// required so the mock fns are available when vi.mock is hoisted above imports.
const {
  mockRedisGetXtmAgentResponse,
  mockRedisSetXtmAgentResponse,
  mockRedisDeleteXtmAgentResponse,
} = vi.hoisted(() => ({
  mockRedisGetXtmAgentResponse: vi.fn(() => Promise.resolve(null)),
  mockRedisSetXtmAgentResponse: vi.fn(() => Promise.resolve()),
  mockRedisDeleteXtmAgentResponse: vi.fn(() => Promise.resolve()),
}));
vi.mock('../../../src/database/redis', () => ({
  getClientBase: vi.fn(() => ({ set: vi.fn(), get: vi.fn(), del: vi.fn() })),
  pubSubSubscription: vi.fn(),
  storeNotifiersForStream: vi.fn(),
  redisSetXtmRegistrationResult: vi.fn(),
  redisGetXtmRegistrationResult: vi.fn(() => null),
  redisGetXtmAgentResponse: mockRedisGetXtmAgentResponse,
  redisSetXtmAgentResponse: mockRedisSetXtmAgentResponse,
  redisDeleteXtmAgentResponse: mockRedisDeleteXtmAgentResponse,
}));

vi.mock('../../../src/lock/master-lock', () => ({
  lockResource: vi.fn(),
}));

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));

vi.mock('../../../src/http/httpServer-draft', () => ({
  checkDraftInContext: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../src/schema/internalObject', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual };
});

vi.mock('../../../src/generated/graphql', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual };
});

vi.mock('../../../src/modules/settings/licensing', () => ({
  getEnterpriseEditionActivePem: vi.fn(),
  getEnterpriseEditionInfo: vi.fn(),
}));

vi.mock('../../../src/modules/user/user-domain', () => ({
  issueAuthenticationJWT: vi.fn(),
}));

vi.mock('../../../src/domain/xtm-auth', () => ({
  issueXtmJwt: vi.fn(() => Promise.resolve('jwt-token-123')),
  getXtmOneIdentity: vi.fn(),
}));

// Only `setCookieError` is stubbed here. `isBrowserSessionRequest` must stay
// the real implementation — the approval tests below exercise that guard's
// actual logic, and a stub would assert nothing.
vi.mock('../../../src/http/httpUtils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/http/httpUtils')>()),
  setCookieError: vi.fn(),
}));

vi.mock('../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: { isConfigured: vi.fn(() => true) },
}));

// Telemetry counters are fire-and-forget side effects; mocking the manager
// also keeps its heavy transitive dependency graph out of this unit test.
vi.mock('../../../src/manager/telemetryManager', () => ({
  addChatbotMessageCount: vi.fn(),
  addAiInsightRequestCount: vi.fn(),
  addXtmAgentCallCount: vi.fn(),
}));

// Case Autopilot approval gates are decided by the investigation domain, which
// pulls the whole database layer: only its decision entry point is needed.
const mockDecideInvestigationApprovals = vi.fn();
vi.mock('../../../src/modules/investigationRun/investigationRun-domain', () => ({
  decideInvestigationApprovals: (...args: unknown[]) => mockDecideInvestigationApprovals(...args),
}));

// Mock getHttpClient — the core HTTP abstraction
const mockPost = vi.fn();
const mockGet = vi.fn();
const mockDelete = vi.fn();
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => ({
    get: mockGet,
    post: mockPost,
    delete: mockDelete,
    head: vi.fn(),
    call: vi.fn(),
  })),
  getResponseError: (error: unknown) => {
    if (error && typeof error === 'object' && 'response' in error) {
      const e = error as any;
      if (e.response) {
        return { status: e.response.status, data: e.response.data, headers: {}, message: e.message };
      }
    }
    return null;
  },
}));

// ── Imports (after mocks) ──────────────────────────────────────────────────

import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { getEntityFromCache } from '../../../src/database/cache';
import { getEnterpriseEditionActivePem, getEnterpriseEditionInfo } from '../../../src/modules/settings/licensing';
import { getXtmOneIdentity } from '../../../src/domain/xtm-auth';
import xtmOneClient from '../../../src/modules/xtm/one/xtm-one-client';
import {
  deleteChatbotMessageFeedback,
  deleteChatbotSession,
  getChatbotConfig,
  getChatbotFileDownload,
  getChatbotPendingApprovals,
  getChatbotPrompts,
  getChatbotQuota,
  getChatbotSessions,
  postAgentMessageStream,
  postChatbotMessageApprove,
  postChatbotMessageFeedback,
  postChatbotMessageSteer,
} from '../../../src/http/httpChatbotProxy';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { logApp } from '../../../src/config/conf';

// ── Helpers ────────────────────────────────────────────────────────────────

const buildReq = (body?: Record<string, unknown>) => ({ body, headers: {} } as any);

// A request as it arrives from a signed-in browser: session cookie resolved to
// the same identity `setupAuthenticatedContext` authenticates, and no bearer
// token. The approval routes accept nothing else.
const buildSessionReq = (body?: Record<string, unknown>, overrides: Record<string, unknown> = {}) => ({
  body,
  headers: {},
  session: { user: { id: 'user-1' } },
  ...overrides,
} as any);

const buildRes = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  res.sendStatus = vi.fn().mockReturnValue(res);
  res.setHeader = vi.fn().mockReturnValue(res);
  res.set = vi.fn().mockReturnValue(res);
  res.write = vi.fn().mockReturnValue(res);
  res.end = vi.fn().mockReturnValue(res);
  return res;
};

/** Configure all mocks so that authentication + license + CGU pass. */
const setupAuthenticatedContext = (overrides: Record<string, unknown> = {}) => {
  const fakeUser = { id: 'user-1', name: 'Test User' };
  const fakeContext = { user: fakeUser, ...overrides };
  vi.mocked(createAuthenticatedContext).mockResolvedValue(fakeContext as any);
  vi.mocked(getEntityFromCache).mockResolvedValue({ filigran_chatbot_ai_cgu_status: 'enabled' } as any);
  vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'pem-data' } as any);
  vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: true } as any);
};

/** OpenCTI has no Enterprise Edition license of its own. */
const withoutOwnLicense = () => {
  vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: undefined } as any);
  vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: false, license_source: 'OPENCTI_LICENSE' } as any);
};

// ── Tests ──────────────────────────────────────────────────────────────────

describe('httpChatbotProxy: postAgentMessageStream', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    // Default to cache miss so the existing tests exercise the XTM One path.
    mockRedisGetXtmAgentResponse.mockResolvedValue(null);
    mockRedisSetXtmAgentResponse.mockResolvedValue(undefined);
    // Default the draft check to a no-op (live workspace, no draft).
    vi.mocked(checkDraftInContext).mockResolvedValue(undefined);
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);
    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
  });

  it('should return 400 when chatbot is not enabled (CGU disabled)', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ filigran_chatbot_ai_cgu_status: 'disabled' } as any);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Chatbot is not enabled' });
  });

  it('should return 400 when the platform is not in Enterprise Edition', async () => {
    withoutOwnLicense();

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Chatbot is not enabled' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should accept the Enterprise Edition granted by a verified XTM license, without an OpenCTI license', async () => {
    withoutOwnLicense();
    vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: true, license_source: 'XTM_ONE_LICENSE' } as any);
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();
    await postAgentMessageStream(req, res);

    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(fakeStream.pipe).toHaveBeenCalledWith(res);
  });

  it('should return 400 when agent_slug is missing', async () => {
    const req = buildReq({ content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'agent_slug and content are required' });
  });

  it('should return 400 when content is missing', async () => {
    const req = buildReq({ agent_slug: 'test-agent' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'agent_slug and content are required' });
  });

  it('should return 400 when body is undefined', async () => {
    const req = buildReq(undefined);

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'agent_slug and content are required' });
  });

  it('should stream response from XTM One on success', async () => {
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, body, opts] = mockPost.mock.calls[0];

    expect(url).toBe('/api/v1/platform/chat/messages');
    expect(body.agent_slug).toBe('test-agent');
    expect(body.content).toBe('hello');
    expect(body.stream).toBe(true);
    expect(opts.timeout).toBe(0);

    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
    expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-cache, no-transform');
    expect(res.setHeader).toHaveBeenCalledWith('Connection', 'keep-alive');
    expect(res.setHeader).toHaveBeenCalledWith('X-Accel-Buffering', 'no');
    expect(fakeStream.pipe).toHaveBeenCalledWith(res);
  });

  it('should destroy stream when client disconnects', async () => {
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    const closeHandler = (req as any).on.mock.calls.find((c: any) => c[0] === 'close')?.[1];
    expect(closeHandler).toBeDefined();
    closeHandler();
    expect(fakeStream.destroy).toHaveBeenCalled();
  });

  it('should return SSE error when HTTP error with response is thrown', async () => {
    const httpError = new Error('Bad request') as any;
    httpError.response = { status: 400, data: { detail: 'Invalid agent' } };
    mockPost.mockRejectedValue(httpError);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
    expect(res.write).toHaveBeenCalledWith(
      expect.stringContaining('"type":"error"'),
    );
    expect(res.write).toHaveBeenCalledWith(
      expect.stringContaining('Invalid agent'),
    );
    expect(res.end).toHaveBeenCalled();
  });

  it('should extract the message when the upstream detail is an object', async () => {
    // XTM One refuses with `{detail: {code, message}}`; interpolating that
    // object reached the chat bubble as "[object Object]".
    const httpError = new Error('Request failed with status code 403') as any;
    httpError.response = { status: 403, data: { detail: { code: 'ai_disabled', message: 'AI is disabled on this deployment.' } } };
    mockPost.mockRejectedValue(httpError);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.write).toHaveBeenCalledWith(
      expect.stringContaining('AI is disabled on this deployment.'),
    );
    expect(res.write).not.toHaveBeenCalledWith(
      expect.stringContaining('[object Object]'),
    );
    expect(res.end).toHaveBeenCalled();
  });

  it('should fall back to error message when HTTP response has no detail', async () => {
    const httpError = new Error('Server error') as any;
    httpError.response = { status: 500, data: {} };
    mockPost.mockRejectedValue(httpError);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.write).toHaveBeenCalledWith(
      expect.stringContaining('Server error'),
    );
    expect(res.end).toHaveBeenCalled();
  });

  it('should return 503 when a non-HTTP error is thrown', async () => {
    mockPost.mockRejectedValue(new Error('Network failure'));

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 503, error: 'XTM One is unreachable' });
    // Regression guard: must NOT leak SSE response headers into a JSON
    // error body. SSE headers are only set once the upstream stream is
    // actually open (or we hit a cache replay) — never on the JSON 503 path.
    expect(res.setHeader).not.toHaveBeenCalledWith('Content-Type', 'text/event-stream');
  });

  it('should serve a cached response as a single SSE done event without calling XTM One', async () => {
    mockRedisGetXtmAgentResponse.mockResolvedValue({
      content: '<p>Cached summary content</p>',
      cached_at: '2026-05-28T10:00:00.000Z',
    } as any);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    await postAgentMessageStream(req, res);

    expect(mockPost).not.toHaveBeenCalled();
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
    expect(res.write).toHaveBeenCalledTimes(1);
    const written = (res.write as any).mock.calls[0][0] as string;
    expect(written).toContain('"type":"done"');
    expect(written).toContain('"cached":true');
    expect(written).toContain('Cached summary content');
    expect(written).toContain('2026-05-28T10:00:00.000Z');
    expect(res.end).toHaveBeenCalled();
  });

  it('should bypass the cache when force_refresh is true', async () => {
    mockRedisGetXtmAgentResponse.mockResolvedValue({
      content: '<p>Cached summary content</p>',
      cached_at: '2026-05-28T10:00:00.000Z',
    } as any);
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello', force_refresh: true });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    expect(mockRedisGetXtmAgentResponse).not.toHaveBeenCalled();
    expect(mockPost).toHaveBeenCalledTimes(1);
    expect(fakeStream.pipe).toHaveBeenCalledWith(res);
  });

  it('should store the final SSE done content in Redis after the stream completes', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    // Simulate the upstream stream emitting tokens then a final done event.
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"stream","content":"Hel"}\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"stream","content":"Hello"}\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"Hello world"}\n\n')));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).toHaveBeenCalledTimes(1);
    const [cacheKey, storedContent, ttlSeconds] = mockRedisSetXtmAgentResponse.mock.calls[0] as any;
    expect(typeof cacheKey).toBe('string');
    expect(cacheKey).toHaveLength(64); // sha256 hex length
    expect(storedContent).toBe('Hello world');
    expect(ttlSeconds).toBeGreaterThan(0);
  });

  it('should not cache a turn that stopped for human approval', async () => {
    // AI Insights never declares `supports_tool_approval`, so a gated tool ends
    // its turn with this prose. Caching it would pin "I need approval before
    // running X" to the entity for the whole TTL (24h by default) and replay it
    // to every user, long after an administrator whitelists the tool.
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'summarize this report' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    const approvalMessage = 'I need approval before running: opencti_delete_entity.\n\nThis chat can\'t collect that approval, so I\'ve stopped rather than acting without it.';
    dataHandlers.forEach((h) => h(Buffer.from(`data: ${JSON.stringify({ type: 'done', content: approvalMessage })}\n\n`)));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should not cache an answer that stops for approval only after some prose', async () => {
    // The agent can answer part of the question and then stop. A prefix-only test
    // would let this half-answer be cached with a stale approval request attached.
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'summarize this report' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    const mixed = 'Here is what I found so far about this entity.\n\nI need approval before running: opencti_delete_entity.';
    dataHandlers.forEach((h) => h(Buffer.from(`data: ${JSON.stringify({ type: 'done', content: mixed })}\n\n`)));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should evict an approval notice cached by an earlier build instead of replaying it', async () => {
    // Redis outlives the deployment that wrote the entry, so the write guard alone
    // cannot clear one. It must be dropped on read.
    mockRedisGetXtmAgentResponse.mockResolvedValue({
      content: 'I need approval before running: opencti_delete_entity.',
      cached_at: '2026-08-20T10:00:00.000Z',
    } as any);
    const fakeStream = { pipe: vi.fn(), destroy: vi.fn(), on: vi.fn().mockReturnThis() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'summarize this report' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    expect(mockRedisDeleteXtmAgentResponse).toHaveBeenCalledTimes(1);
    // Not replayed to the client...
    expect(res.write).not.toHaveBeenCalled();
    // ...and the turn falls through to a live agent run.
    expect(mockPost).toHaveBeenCalled();
  });

  it('should not cache the response when the stream emits an error event', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"stream","content":"partial"}\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"error","content":"Quota exceeded"}\n\n')));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should not cache the response when the client aborts mid-stream', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    const reqOn = vi.fn();
    (req as any).on = reqOn;

    await postAgentMessageStream(req, res);

    // Trigger client close before the stream emits a done event.
    const closeHandler = reqOn.mock.calls.find((c: any[]) => c[0] === 'close')?.[1];
    expect(closeHandler).toBeDefined();
    closeHandler();

    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"partial"}\n\n')));
    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should tolerate malformed SSE lines and still cache the final done content', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    // Mix of: a heartbeat comment, a non-`data:` line, a malformed JSON
    // payload, and finally a valid `done` event.
    dataHandlers.forEach((h) => h(Buffer.from(': heartbeat\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('event: ping\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('data: {not valid json}\n\n')));
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"final"}\n\n')));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).toHaveBeenCalledTimes(1);
    const [, storedContent] = mockRedisSetXtmAgentResponse.mock.calls[0] as any;
    expect(storedContent).toBe('final');
  });

  it('should not cache when the stream completes without a done event', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"stream","content":"partial"}\n\n')));
    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should reject with 400 when the draft context fails validation, without calling cache or upstream', async () => {
    // Simulate a caller passing an `opencti-draft-id` they do not have access
    // to (or that is closed). The REST proxy MUST refuse — without this guard
    // a cached response (or a fresh agent run) computed for another draft
    // could be replayed across draft authorization boundaries.
    setupAuthenticatedContext({ draft_context: 'forged-draft-id' });
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Could not find draft workspace'));
    mockRedisGetXtmAgentResponse.mockResolvedValue({
      content: '<p>This MUST NEVER be replayed</p>',
      cached_at: '2026-05-28T10:00:00.000Z',
    } as any);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Could not find draft workspace' });
    expect(mockRedisGetXtmAgentResponse).not.toHaveBeenCalled();
    expect(mockPost).not.toHaveBeenCalled();
    // Also verify no SSE headers leaked into the JSON 400 response.
    expect(res.setHeader).not.toHaveBeenCalledWith('Content-Type', 'text/event-stream');
  });

  it('should derive the cache key from context.draft_context, not the raw header', async () => {
    // Two requests with the same agent + prompt but different
    // `context.draft_context` values must produce different cache keys, so a
    // live-workspace cache hit cannot leak into a draft view (and vice-versa).
    // We capture the cache key written on stream completion and assert the
    // two are distinct.
    const captureCacheKey = async (draftContext: string | undefined) => {
      vi.clearAllMocks();
      setupAuthenticatedContext(draftContext === undefined ? {} : { draft_context: draftContext });
      vi.mocked(checkDraftInContext).mockResolvedValue(undefined);
      mockRedisGetXtmAgentResponse.mockResolvedValue(null);
      mockRedisSetXtmAgentResponse.mockResolvedValue(undefined);
      const dataHandlers: ((chunk: Buffer) => void)[] = [];
      const endHandlers: (() => void | Promise<void>)[] = [];
      const fakeStream = {
        pipe: vi.fn(),
        destroy: vi.fn(),
        on: vi.fn((event: string, handler: any) => {
          if (event === 'data') dataHandlers.push(handler);
          if (event === 'end') endHandlers.push(handler);
          return fakeStream;
        }),
      };
      mockPost.mockResolvedValue({ data: fakeStream });
      const req = buildReq({ agent_slug: 'same-agent', content: 'same prompt' });
      (req as any).on = vi.fn();
      const localRes = buildRes();
      await postAgentMessageStream(req, localRes);
      dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"final"}\n\n')));
      await Promise.all(endHandlers.map((h) => h()));
      const [cacheKey] = mockRedisSetXtmAgentResponse.mock.calls[0] as any;
      return cacheKey as string;
    };

    const liveKey = await captureCacheKey(undefined);
    const draftKey = await captureCacheKey('draft-123');
    expect(liveKey).toHaveLength(64);
    expect(draftKey).toHaveLength(64);
    expect(liveKey).not.toEqual(draftKey);
  });

  it('should forward context.draft_context to XTM One even when the request header is empty', async () => {
    // Regression guard for the cache-vs-upstream draft mismatch:
    // `context.draft_context` falls back to `user.draft_context` when the
    // request omits `opencti-draft-id`, so without the explicit override
    // `generateBasicHeaders` would forward an empty draft header while the
    // cache key was scoped to the user's session draft — running the agent
    // live but storing the result under the draft key.
    setupAuthenticatedContext({ draft_context: 'user-session-draft-id' });
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    // The mocked HTTP client factory is invoked with the headers we want to assert
    // on, but we only have access to the post() mock. Instead, verify by checking
    // that the http-client `getHttpClient` mock was called with headers including
    // the right draft id.
    const { getHttpClient } = await import('../../../src/utils/http-client');
    const headerCalls = vi.mocked(getHttpClient).mock.calls
      .map((c) => c[0]?.headers)
      .filter((h): h is Record<string, string> => !!h && 'opencti-draft-id' in h);
    expect(headerCalls.length).toBeGreaterThan(0);
    expect(headerCalls[headerCalls.length - 1]['opencti-draft-id']).toBe('user-session-draft-id');
  });

  it('should not cache when the upstream stream emits a Node `error` event', async () => {
    // Belt-and-suspenders guard for transport errors. Node typically does
    // not emit `'end'` after `'error'`, but if a future runtime/library
    // version reordered events, we'd otherwise risk caching a partial or
    // failed response. Simulate the upstream emitting a fully-formed `done`
    // SSE chunk, then a Node-level `'error'`, then `'end'` — we MUST not
    // call `redisSetXtmAgentResponse` even though `extractFinalContent`
    // would otherwise return a non-null value.
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const errorHandlers: ((error: Error) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'error') errorHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"complete"}\n\n')));
    errorHandlers.forEach((h) => h(new Error('socket hang up')));
    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });

  it('should skip caching when the upstream response exceeds the 2MB capture limit', async () => {
    const dataHandlers: ((chunk: Buffer) => void)[] = [];
    const endHandlers: (() => void | Promise<void>)[] = [];
    const fakeStream = {
      pipe: vi.fn(),
      destroy: vi.fn(),
      on: vi.fn((event: string, handler: any) => {
        if (event === 'data') dataHandlers.push(handler);
        if (event === 'end') endHandlers.push(handler);
        return fakeStream;
      }),
    };
    mockPost.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    // Push 3MB of bytes — well above the 2MB capture ceiling.
    const oneMb = Buffer.alloc(1024 * 1024, 0x41);
    dataHandlers.forEach((h) => h(oneMb));
    dataHandlers.forEach((h) => h(oneMb));
    dataHandlers.forEach((h) => h(oneMb));
    dataHandlers.forEach((h) => h(Buffer.from('data: {"type":"done","content":"final"}\n\n')));

    await Promise.all(endHandlers.map((h) => h()));

    expect(mockRedisSetXtmAgentResponse).not.toHaveBeenCalled();
  });
});

describe('httpChatbotProxy: getChatbotFileDownload', () => {
  const VALID_FILE_ID = '11111111-1111-1111-1111-111111111111';
  let res: ReturnType<typeof buildRes>;

  const buildDownloadReq = (fileId: string) => ({ params: { fileId }, headers: {}, on: vi.fn() } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    // Default the draft check to a no-op (live workspace, no draft).
    vi.mocked(checkDraftInContext).mockResolvedValue(undefined);
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotFileDownload(buildDownloadReq(VALID_FILE_ID), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID file id without calling XTM One', async () => {
    await getChatbotFileDownload(buildDownloadReq('../etc/passwd'), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid file id' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should reject with 400 when the draft context fails validation, without calling XTM One', async () => {
    // Simulate a caller forging an `opencti-draft-id` they cannot access (or a
    // closed draft). The REST proxy MUST refuse before reaching XTM One —
    // without this guard a draft-scoped file could be downloaded across draft
    // authorization boundaries.
    setupAuthenticatedContext({ draft_context: 'forged-draft-id' });
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Could not find draft workspace'));

    await getChatbotFileDownload(buildDownloadReq(VALID_FILE_ID), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Could not find draft workspace' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should forward the validated context.draft_context to XTM One, not the raw request header', async () => {
    // File downloads are frequently triggered without custom headers, so the
    // upstream draft id must come from the validated `context.draft_context`
    // (which falls back to the user's session draft) rather than the raw
    // request header — otherwise a draft user would hit the live workspace.
    setupAuthenticatedContext({ draft_context: 'user-session-draft-id' });
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockGet.mockResolvedValue({ data: fakeStream, headers: {} });

    await getChatbotFileDownload(buildDownloadReq(VALID_FILE_ID), res);

    const { getHttpClient } = await import('../../../src/utils/http-client');
    const headerCalls = vi.mocked(getHttpClient).mock.calls
      .map((c) => c[0]?.headers)
      .filter((h): h is Record<string, string> => !!h && 'opencti-draft-id' in h);
    expect(headerCalls.length).toBeGreaterThan(0);
    expect(headerCalls[headerCalls.length - 1]['opencti-draft-id']).toBe('user-session-draft-id');
    expect(mockGet).toHaveBeenCalledTimes(1);
  });

  it('should stream the file and forward content headers on success', async () => {
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockGet.mockResolvedValue({
      data: fakeStream,
      headers: {
        'content-type': 'text/csv',
        'content-disposition': 'attachment; filename="iocs.csv"',
        'content-length': '21',
        'content-encoding': 'gzip',
        'cache-control': 'private, max-age=86400',
        'x-should-not-forward': 'secret',
      },
    });

    const req = buildDownloadReq(VALID_FILE_ID);
    await getChatbotFileDownload(req, res);

    expect(mockGet).toHaveBeenCalledTimes(1);
    const [url, opts] = mockGet.mock.calls[0];
    expect(url).toBe(`/api/v1/chat/files/${VALID_FILE_ID}/download`);
    expect(opts.timeout).toBe(0);
    expect(opts.decompress).toBe(false);

    expect(res.setHeader).toHaveBeenCalledWith('content-type', 'text/csv');
    expect(res.setHeader).toHaveBeenCalledWith('content-disposition', 'attachment; filename="iocs.csv"');
    expect(res.setHeader).toHaveBeenCalledWith('content-length', '21');
    expect(res.setHeader).toHaveBeenCalledWith('content-encoding', 'gzip');
    expect(res.setHeader).toHaveBeenCalledWith('cache-control', 'private, max-age=86400');
    // Non-allowlisted upstream headers must not be forwarded.
    expect(res.setHeader).not.toHaveBeenCalledWith('x-should-not-forward', 'secret');
    expect(fakeStream.pipe).toHaveBeenCalledWith(res);
  });

  it('should destroy the upstream stream when the client disconnects', async () => {
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockGet.mockResolvedValue({ data: fakeStream, headers: {} });

    const req = buildDownloadReq(VALID_FILE_ID);
    await getChatbotFileDownload(req, res);

    const closeHandler = req.on.mock.calls.find((c: any[]) => c[0] === 'close')?.[1];
    expect(closeHandler).toBeDefined();
    closeHandler();
    expect(fakeStream.destroy).toHaveBeenCalled();
  });

  it('should propagate the upstream status and detail message on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'File not found' } };
    mockGet.mockRejectedValue(httpError);

    await getChatbotFileDownload(buildDownloadReq(VALID_FILE_ID), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'File not found' });
  });

  it('should return 503 when a non-HTTP error is thrown', async () => {
    mockGet.mockRejectedValue(new Error('Network failure'));

    await getChatbotFileDownload(buildDownloadReq(VALID_FILE_ID), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith({ error: 'XTM One is unreachable' });
  });
});

describe('httpChatbotProxy: getChatbotSessions', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotSessions(buildReq(), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should forward the upstream status and body on success', async () => {
    const sessions = [{ conversation_id: '11111111-1111-1111-1111-111111111111', title: 'Threat recap' }];
    mockGet.mockResolvedValue({ status: 200, data: sessions });

    await getChatbotSessions(buildReq(), res);

    expect(mockGet).toHaveBeenCalledTimes(1);
    const [url, opts] = mockGet.mock.calls[0];
    expect(url).toBe('/api/v1/platform/chat/sessions');
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(sessions);
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 502') as any;
    httpError.response = { status: 502, data: { detail: 'Chat history unavailable' } };
    mockGet.mockRejectedValue(httpError);

    await getChatbotSessions(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(502);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Chat history unavailable' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockGet.mockRejectedValue(new Error('Network failure'));

    await getChatbotSessions(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: deleteChatbotSession', () => {
  const VALID_CONVERSATION_ID = '22222222-2222-2222-2222-222222222222';
  let res: ReturnType<typeof buildRes>;

  const buildDeleteReq = (conversationId: string) => ({ params: { conversationId }, headers: {} } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await deleteChatbotSession(buildDeleteReq(VALID_CONVERSATION_ID), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockDelete).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID conversation id without calling XTM One', async () => {
    await deleteChatbotSession(buildDeleteReq('../other-tenant/conversations'), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid conversation id' });
    expect(mockDelete).not.toHaveBeenCalled();
  });

  it('should forward an upstream 204 with an empty body', async () => {
    mockDelete.mockResolvedValue({ status: 204, data: '' });

    await deleteChatbotSession(buildDeleteReq(VALID_CONVERSATION_ID), res);

    expect(mockDelete).toHaveBeenCalledTimes(1);
    const [url] = mockDelete.mock.calls[0];
    expect(url).toBe(`/api/v1/platform/chat/sessions/${VALID_CONVERSATION_ID}`);
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
    // Must not inject a textual ("No Content") or JSON body on empty upstream responses.
    expect(res.json).not.toHaveBeenCalled();
    expect(res.sendStatus).not.toHaveBeenCalled();
  });

  it('should forward an upstream 200 with its JSON body', async () => {
    mockDelete.mockResolvedValue({ status: 200, data: { archived: true } });

    await deleteChatbotSession(buildDeleteReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ archived: true });
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'Conversation not found' } };
    mockDelete.mockRejectedValue(httpError);

    await deleteChatbotSession(buildDeleteReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Conversation not found' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockDelete.mockRejectedValue(new Error('Network failure'));

    await deleteChatbotSession(buildDeleteReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: postChatbotMessageSteer', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await postChatbotMessageSteer(buildReq({ conversation_id: 'c-1', content: 'steer this' }), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return 400 when the body is missing', async () => {
    await postChatbotMessageSteer(buildReq(undefined), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Request body is missing' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should forward the body and the upstream status on success', async () => {
    mockPost.mockResolvedValue({ status: 202, data: { message_id: 'm-1' } });
    const body = { conversation_id: 'c-1', content: 'focus on the APT41 angle', agent_slug: 'global.assistant' };

    await postChatbotMessageSteer(buildReq(body), res);

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, sentBody, opts] = mockPost.mock.calls[0];
    expect(url).toBe('/api/v1/platform/chat/messages/steer');
    expect(sentBody).toEqual(body);
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(202);
    expect(res.json).toHaveBeenCalledWith({ message_id: 'm-1' });
  });

  it('should forward an upstream 409 with its detail so the widget rolls back the optimistic bubble', async () => {
    const httpError = new Error('Request failed with status code 409') as any;
    httpError.response = { status: 409, data: { detail: 'No response is currently being generated' } };
    mockPost.mockRejectedValue(httpError);

    await postChatbotMessageSteer(buildReq({ conversation_id: 'c-1', content: 'steer' }), res);

    expect(res.status).toHaveBeenCalledWith(409);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'No response is currently being generated' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockPost.mockRejectedValue(new Error('Network failure'));

    await postChatbotMessageSteer(buildReq({ conversation_id: 'c-1', content: 'steer' }), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: postChatbotMessageApprove', () => {
  let res: ReturnType<typeof buildRes>;

  const APPROVAL_BODY = {
    conversation_id: '33333333-3333-3333-3333-333333333333',
    decisions: [
      { tool_call_id: 'call_abc123', decision: 'approve' },
      { tool_call_id: 'call_ghi789', decision: 'reject', rejection_reason: 'Wrong target environment.' },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // The widget always reaches this route from a browser session.
    setupAuthenticatedContext({ user_with_session: true });
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await postChatbotMessageApprove(buildReq(APPROVAL_BODY), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should refuse a token-authenticated identity without a session', async () => {
    // An agent or service account must never be able to approve a tool call —
    // least of all one it proposed itself.
    setupAuthenticatedContext({ user_with_session: false });

    await postChatbotMessageApprove(buildSessionReq(APPROVAL_BODY), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'Tool approval requires a user session' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should refuse a bearer token presented alongside a session cookie', async () => {
    // `authenticateUserFromRequest` returns on the bearer branch before it looks
    // at the session, so a service token plus any user's cookie authenticates as
    // the token identity while `user_with_session` still reports true. That
    // combination must not be able to approve a call the token identity proposed.
    await postChatbotMessageApprove(
      buildSessionReq(APPROVAL_BODY, { headers: { authorization: 'Bearer service-token' } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'Tool approval requires a user session' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should refuse a session belonging to a different identity than the authenticated one', async () => {
    await postChatbotMessageApprove(
      buildSessionReq(APPROVAL_BODY, { session: { user: { id: 'someone-else' } } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'Tool approval requires a user session' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return 400 when the body is missing', async () => {
    await postChatbotMessageApprove(buildSessionReq(undefined), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Request body is missing' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should forward the decisions body whole and pass the upstream status through', async () => {
    mockPost.mockResolvedValue({ status: 200, data: { status: 'accepted', decided: 2 } });

    await postChatbotMessageApprove(buildSessionReq(APPROVAL_BODY), res);

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, sentBody, opts] = mockPost.mock.calls[0];
    expect(url).toBe('/api/v1/platform/chat/messages/approve');
    // Forwarded untouched — a rebuilt body would drop `rejection_reason`, which
    // is the only thing the agent has to adapt to a declined call.
    expect(sentBody).toEqual(APPROVAL_BODY);
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'accepted', decided: 2 });
  });

  it('should forward an upstream 409 so the widget knows nothing is waiting any more', async () => {
    const httpError = new Error('Request failed with status code 409') as any;
    httpError.response = { status: 409, data: { detail: 'No turn is currently awaiting approval for this conversation' } };
    mockPost.mockRejectedValue(httpError);

    await postChatbotMessageApprove(buildSessionReq(APPROVAL_BODY), res);

    expect(res.status).toHaveBeenCalledWith(409);
    expect(res.send).toHaveBeenCalledWith({
      status: 'error',
      error: 'No turn is currently awaiting approval for this conversation',
    });
  });

  it('should forward an upstream 422 for a partial decision set', async () => {
    const httpError = new Error('Request failed with status code 422') as any;
    httpError.response = { status: 422, data: { detail: 'Missing decisions for: call_ghi789' } };
    mockPost.mockRejectedValue(httpError);

    await postChatbotMessageApprove(buildSessionReq(APPROVAL_BODY), res);

    expect(res.status).toHaveBeenCalledWith(422);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Missing decisions for: call_ghi789' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockPost.mockRejectedValue(new Error('Network failure'));

    await postChatbotMessageApprove(buildSessionReq(APPROVAL_BODY), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: postChatbotMessageApprove for Case Autopilot runs', () => {
  let res: ReturnType<typeof buildRes>;
  const RUN_ID = '55555555-5555-4555-8555-555555555555';
  const APPROVAL_ID = '66666666-6666-4666-8666-666666666666';
  const RUN_BODY = {
    investigation_run_id: RUN_ID,
    decisions: [{ tool_call_id: APPROVAL_ID, decision: 'approve' }],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext({ user_with_session: true });
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should decide the run approvals in OpenCTI and never call XTM One', async () => {
    mockDecideInvestigationApprovals.mockResolvedValue({ decided: 1, run: { id: RUN_ID } });

    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);

    expect(mockPost).not.toHaveBeenCalled();
    expect(mockDecideInvestigationApprovals).toHaveBeenCalledTimes(1);
    const [, user, runId, decisions] = mockDecideInvestigationApprovals.mock.calls[0];
    expect(user).toEqual({ id: 'user-1', name: 'Test User' });
    expect(runId).toEqual(RUN_ID);
    expect(decisions).toEqual([{ tool_call_id: APPROVAL_ID, decision: 'approve', rejection_reason: null }]);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'accepted', decided: 1 });
  });

  it('should still require a browser session', async () => {
    setupAuthenticatedContext({ user_with_session: false });

    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(mockDecideInvestigationApprovals).not.toHaveBeenCalled();
  });

  it('should refuse a malformed run id or decision', async () => {
    await postChatbotMessageApprove(buildSessionReq({ ...RUN_BODY, investigation_run_id: 'not-a-uuid' }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid investigation run id' });

    res = buildRes();
    await postChatbotMessageApprove(buildSessionReq({ ...RUN_BODY, decisions: [{ tool_call_id: APPROVAL_ID, decision: 'maybe' }] }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid decision' });

    res = buildRes();
    await postChatbotMessageApprove(buildSessionReq({ ...RUN_BODY, decisions: [] }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'No decisions supplied' });

    res = buildRes();
    const tooMany = Array.from({ length: 101 }, () => ({ tool_call_id: APPROVAL_ID, decision: 'approve' }));
    await postChatbotMessageApprove(buildSessionReq({ ...RUN_BODY, decisions: tooMany }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: expect.stringContaining('Too many decisions') });

    res = buildRes();
    await postChatbotMessageApprove(buildSessionReq({
      ...RUN_BODY,
      decisions: [{ tool_call_id: APPROVAL_ID, decision: 'approve' }, { tool_call_id: APPROVAL_ID, decision: 'approve_always' }],
    }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Each approval can be decided once per request' });
    expect(mockDecideInvestigationApprovals).not.toHaveBeenCalled();
  });

  it('should answer 409 when nothing is waiting for these decisions', async () => {
    mockDecideInvestigationApprovals.mockResolvedValue({ decided: 0, run: { id: RUN_ID } });

    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);

    expect(res.status).toHaveBeenCalledWith(409);
  });

  it('should map forbidden and unknown runs to 403 and 404', async () => {
    mockDecideInvestigationApprovals.mockRejectedValueOnce({ message: 'You are not allowed to decide this approval', extensions: { code: 'FORBIDDEN_ACCESS' } });
    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);
    expect(res.status).toHaveBeenCalledWith(403);

    res = buildRes();
    mockDecideInvestigationApprovals.mockRejectedValueOnce({ message: 'Investigation run not found' });
    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);
    expect(res.status).toHaveBeenCalledWith(404);
  });

  it('should answer a business refusal with 400 and a platform failure with 500, logged as a warning and an error', async () => {
    mockDecideInvestigationApprovals.mockRejectedValueOnce({ message: 'This investigation has ended', extensions: { code: 'FUNCTIONAL_ERROR' } });
    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'This investigation has ended' });
    expect(logApp.warn).toHaveBeenCalledWith('Investigation approval refused', expect.objectContaining({ runId: RUN_ID }));
    expect(logApp.error).not.toHaveBeenCalled();

    res = buildRes();
    mockDecideInvestigationApprovals.mockRejectedValueOnce(new Error('Connection lost'));
    await postChatbotMessageApprove(buildSessionReq(RUN_BODY), res);
    expect(res.status).toHaveBeenCalledWith(500);
    // The cause of a failure is logged, never sent to the client.
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'Approval failed' });
    expect(logApp.error).toHaveBeenCalledWith('Error in investigation approval', expect.objectContaining({ runId: RUN_ID }));
  });
});

describe('httpChatbotProxy: getChatbotPendingApprovals', () => {
  const VALID_CONVERSATION_ID = '44444444-4444-4444-4444-444444444444';
  let res: ReturnType<typeof buildRes>;

  const buildPendingReq = (conversationId: string, overrides: Record<string, unknown> = {}) => ({
    params: { conversationId },
    headers: {},
    session: { user: { id: 'user-1' } },
    ...overrides,
  } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext({ user_with_session: true });
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should refuse a token-authenticated identity without a session', async () => {
    // The proposals payload spells out the tool, its arguments and its schema, and
    // reaching this route also keeps a displayed prompt from being treated as
    // abandoned. Neither is an API token's business.
    setupAuthenticatedContext({ user_with_session: false });

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID, { session: undefined }), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ status: 'error', error: 'Tool approval requires a user session' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID conversation id without calling XTM One', async () => {
    await getChatbotPendingApprovals(buildPendingReq('../other-tenant/conversations'), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid conversation id' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should forward the recovered proposals and the turn state', async () => {
    const upstream = {
      conversation_id: VALID_CONVERSATION_ID,
      proposals: [{
        tool_call_id: 'call_abc123',
        tool_name: 'opencti_delete_entity',
        arguments: { entity_id: 'e-123', cascade: true },
        input_schema: { type: 'object', properties: { cascade: { type: 'boolean', description: 'Also delete linked entities' } } },
      }],
      turn: 'running',
    };
    mockGet.mockResolvedValue({ status: 200, data: upstream });

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID), res);

    expect(mockGet).toHaveBeenCalledTimes(1);
    const [url] = mockGet.mock.calls[0];
    expect(url).toBe(`/api/v1/platform/chat/conversations/${VALID_CONVERSATION_ID}/pending-approvals`);
    expect(res.status).toHaveBeenCalledWith(200);
    // `input_schema` must survive the hop: without each argument's description
    // the prompt is a rubber stamp.
    expect(res.json).toHaveBeenCalledWith(upstream);
  });

  it('should forward an empty proposals list as the ordinary answer', async () => {
    mockGet.mockResolvedValue({ status: 200, data: { conversation_id: VALID_CONVERSATION_ID, proposals: [], turn: 'idle' } });

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ conversation_id: VALID_CONVERSATION_ID, proposals: [], turn: 'idle' });
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'Conversation not found' } };
    mockGet.mockRejectedValue(httpError);

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Conversation not found' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockGet.mockRejectedValue(new Error('Network failure'));

    await getChatbotPendingApprovals(buildPendingReq(VALID_CONVERSATION_ID), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: getChatbotPrompts', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotPrompts(buildReq(), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should forward the upstream status and body on success', async () => {
    const prompts = {
      prompts: [{ id: 'p-1', title: 'Weekly recap', content: 'Summarize this week in threat intel', description: null }],
    };
    mockGet.mockResolvedValue({ status: 200, data: prompts });

    await getChatbotPrompts(buildReq(), res);

    expect(mockGet).toHaveBeenCalledTimes(1);
    const [url, opts] = mockGet.mock.calls[0];
    expect(url).toBe('/api/v1/platform/chat/prompts');
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(prompts);
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'Not Found' } };
    mockGet.mockRejectedValue(httpError);

    await getChatbotPrompts(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Not Found' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockGet.mockRejectedValue(new Error('Network failure'));

    await getChatbotPrompts(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: getChatbotQuota', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotQuota(buildReq(), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('should forward the upstream status and body on success', async () => {
    const quota = { used: 12, limit: 100, period: 'day', scope: 'user' };
    mockGet.mockResolvedValue({ status: 200, data: quota });

    await getChatbotQuota(buildReq(), res);

    expect(mockGet).toHaveBeenCalledTimes(1);
    const [url, opts] = mockGet.mock.calls[0];
    expect(url).toBe('/api/v1/platform/chat/quota');
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(quota);
  });

  it('should forward a null quota as is so the widget hides the indicator', async () => {
    mockGet.mockResolvedValue({ status: 200, data: null });

    await getChatbotQuota(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(null);
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 502') as any;
    httpError.response = { status: 502, data: { detail: 'Quota unavailable' } };
    mockGet.mockRejectedValue(httpError);

    await getChatbotQuota(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(502);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Quota unavailable' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockGet.mockRejectedValue(new Error('Network failure'));

    await getChatbotQuota(buildReq(), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: postChatbotMessageFeedback', () => {
  const VALID_CONVERSATION_ID = '55555555-5555-5555-5555-555555555555';
  const VALID_MESSAGE_ID = '66666666-6666-6666-6666-666666666666';
  const FEEDBACK_URL = `/api/v1/platform/chat/conversations/${VALID_CONVERSATION_ID}/messages/${VALID_MESSAGE_ID}/feedback`;
  let res: ReturnType<typeof buildRes>;

  const buildFeedbackReq = (conversationId: string, messageId: string, body?: Record<string, unknown>) => ({
    params: { conversationId, messageId },
    body,
    headers: {},
  } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID, { rating: 'positive' }), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID conversation id without calling XTM One', async () => {
    await postChatbotMessageFeedback(buildFeedbackReq('../other-tenant', VALID_MESSAGE_ID, { rating: 'positive' }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid conversation id' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID message id without calling XTM One', async () => {
    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, 'm-1/../../admin', { rating: 'positive' }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid message id' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return 400 when the body is missing', async () => {
    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID, undefined), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Request body is missing' });
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should forward the body and the upstream status on success', async () => {
    const body = { rating: 'negative', comment: 'Cited the wrong intrusion set' };
    mockPost.mockResolvedValue({ status: 200, data: body });

    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID, body), res);

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, sentBody, opts] = mockPost.mock.calls[0];
    expect(url).toBe(FEEDBACK_URL);
    expect(sentBody).toEqual(body);
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(body);
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'Message not found' } };
    mockPost.mockRejectedValue(httpError);

    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID, { rating: 'positive' }), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Message not found' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockPost.mockRejectedValue(new Error('Network failure'));

    await postChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID, { rating: 'positive' }), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: deleteChatbotMessageFeedback', () => {
  const VALID_CONVERSATION_ID = '77777777-7777-7777-7777-777777777777';
  const VALID_MESSAGE_ID = '88888888-8888-8888-8888-888888888888';
  let res: ReturnType<typeof buildRes>;

  const buildFeedbackReq = (conversationId: string, messageId: string) => ({
    params: { conversationId, messageId },
    headers: {},
  } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await deleteChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(mockDelete).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID conversation id without calling XTM One', async () => {
    await deleteChatbotMessageFeedback(buildFeedbackReq('not-a-uuid', VALID_MESSAGE_ID), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid conversation id' });
    expect(mockDelete).not.toHaveBeenCalled();
  });

  it('should return 400 for a non-UUID message id without calling XTM One', async () => {
    await deleteChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, ''), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid message id' });
    expect(mockDelete).not.toHaveBeenCalled();
  });

  it('should forward an upstream 204 with an empty body', async () => {
    mockDelete.mockResolvedValue({ status: 204, data: '' });

    await deleteChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID), res);

    expect(mockDelete).toHaveBeenCalledTimes(1);
    const [url, opts] = mockDelete.mock.calls[0];
    expect(url).toBe(`/api/v1/platform/chat/conversations/${VALID_CONVERSATION_ID}/messages/${VALID_MESSAGE_ID}/feedback`);
    expect(opts.timeout).toBeGreaterThan(0);
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
    expect(res.sendStatus).not.toHaveBeenCalled();
  });

  it('should surface the upstream detail and status on HTTP error', async () => {
    const httpError = new Error('Request failed with status code 404') as any;
    httpError.response = { status: 404, data: { detail: 'Message not found' } };
    mockDelete.mockRejectedValue(httpError);

    await deleteChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID), res);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Message not found' });
  });

  it('should fall back to the error message and 503 when no HTTP response is available', async () => {
    mockDelete.mockRejectedValue(new Error('Network failure'));

    await deleteChatbotMessageFeedback(buildFeedbackReq(VALID_CONVERSATION_ID, VALID_MESSAGE_ID), res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Network failure' });
  });
});

describe('httpChatbotProxy: getChatbotConfig', () => {
  let res: ReturnType<typeof buildRes>;

  beforeEach(() => {
    vi.clearAllMocks();
    setupAuthenticatedContext();
    res = buildRes();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should hand the browser the identity XTM One publishes, not the URL OpenCTI reaches it on', async () => {
    vi.mocked(getXtmOneIdentity).mockResolvedValue('http://localhost:8090');

    await getChatbotConfig(buildReq(), res);

    expect(res.json).toHaveBeenCalledWith({ xtm_one_url: 'http://localhost:8090', xtm_one_configured: true });
  });

  it('should serve no URL, without reading XTM One, when XTM One is not configured', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(false);

    await getChatbotConfig(buildReq(), res);

    expect(res.json).toHaveBeenCalledWith({ xtm_one_url: null, xtm_one_configured: false });
    expect(getXtmOneIdentity).not.toHaveBeenCalled();
  });

  it('should return 403 when user is not authenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    await getChatbotConfig(buildReq(), res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(getXtmOneIdentity).not.toHaveBeenCalled();
  });
});
