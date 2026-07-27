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
const { mockRedisGetXtmAgentResponse, mockRedisSetXtmAgentResponse } = vi.hoisted(() => ({
  mockRedisGetXtmAgentResponse: vi.fn(() => Promise.resolve(null)),
  mockRedisSetXtmAgentResponse: vi.fn(() => Promise.resolve()),
}));
vi.mock('../../../src/database/redis', () => ({
  getClientBase: vi.fn(() => ({ set: vi.fn(), get: vi.fn(), del: vi.fn() })),
  pubSubSubscription: vi.fn(),
  storeNotifiersForStream: vi.fn(),
  redisSetXtmRegistrationResult: vi.fn(),
  redisGetXtmRegistrationResult: vi.fn(() => null),
  redisGetXtmAgentResponse: mockRedisGetXtmAgentResponse,
  redisSetXtmAgentResponse: mockRedisSetXtmAgentResponse,
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

vi.mock('../../../src/domain/user', () => ({
  issueAuthenticationJWT: vi.fn(),
}));

vi.mock('../../../src/domain/xtm-auth', () => ({
  issueXtmJwt: vi.fn(() => Promise.resolve('jwt-token-123')),
}));

vi.mock('../../../src/http/httpUtils', () => ({
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
import { deleteChatbotSession, getChatbotFileDownload, getChatbotSessions, postAgentMessageStream, postChatbotMessageSteer } from '../../../src/http/httpChatbotProxy';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';

// ── Helpers ────────────────────────────────────────────────────────────────

const buildReq = (body?: Record<string, unknown>) => ({ body, headers: {} } as any);

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
