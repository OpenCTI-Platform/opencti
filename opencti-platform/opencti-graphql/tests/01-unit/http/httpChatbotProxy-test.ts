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

// Mock getHttpClient — the core HTTP abstraction
const mockPost = vi.fn();
const mockGet = vi.fn();
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => ({
    get: mockGet,
    post: mockPost,
    delete: vi.fn(),
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
import { postAgentMessageStream } from '../../../src/http/httpChatbotProxy';

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
const setupAuthenticatedContext = () => {
  const fakeUser = { id: 'user-1', name: 'Test User' };
  const fakeContext = { user: fakeUser };
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
