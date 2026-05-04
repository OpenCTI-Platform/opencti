import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import axios from 'axios';

// ── Mocks ──────────────────────────────────────────────────────────────────

vi.mock('axios');
const mockedAxios = vi.mocked(axios, true);

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
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  getChatbotUrl: vi.fn(() => 'http://localhost:4000'),
  PLATFORM_VERSION: '6.0.0',
  basePath: '',
  DEV_MODE: false,
  ENABLED_UI: false,
  OPENCTI_SESSION: 'opencti_session',
  AUTH_PAYLOAD_BODY_SIZE: undefined,
  getBaseUrl: vi.fn(() => 'http://localhost:4000'),
}));

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../src/schema/internalObject', () => ({
  ENTITY_TYPE_SETTINGS: 'Settings',
  ENTITY_TYPE_USER: 'User',
}));

vi.mock('../../../src/generated/graphql', () => ({
  CguStatus: { Enabled: 'enabled', Disabled: 'disabled' },
}));

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

vi.mock('../../../src/modules/xtm/one/xtm-one', () => ({
  getDiscoveredIntentCatalog: vi.fn(() => []),
}));

vi.mock('../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: { isConfigured: vi.fn(() => true) },
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
    mockedAxios.post.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    const [url, rawBody, rawConfig] = mockedAxios.post.mock.calls[0];
    const body = rawBody as Record<string, any>;
    const config = rawConfig as Record<string, any>;

    expect(url).toBe('http://xtm-one/api/v1/platform/chat/messages');
    expect(body.agent_slug).toBe('test-agent');
    expect(body.content).toBe('hello');
    expect(body.stream).toBe(true);
    expect(config.headers.Authorization).toBe('Bearer jwt-token-123');
    expect(config.responseType).toBe('stream');
    expect(config.timeout).toBe(0);

    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
    expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-cache, no-transform');
    expect(res.setHeader).toHaveBeenCalledWith('Connection', 'keep-alive');
    expect(res.setHeader).toHaveBeenCalledWith('X-Accel-Buffering', 'no');
    expect(fakeStream.pipe).toHaveBeenCalledWith(res);
  });

  it('should destroy stream when client disconnects', async () => {
    const fakeStream = { pipe: vi.fn(), on: vi.fn(), destroy: vi.fn() };
    mockedAxios.post.mockResolvedValue({ data: fakeStream });

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });
    (req as any).on = vi.fn();

    await postAgentMessageStream(req, res);

    const closeHandler = (req as any).on.mock.calls.find((c: any) => c[0] === 'close')?.[1];
    expect(closeHandler).toBeDefined();
    closeHandler();
    expect(fakeStream.destroy).toHaveBeenCalled();
  });

  it('should return SSE error when axios returns an error with response', async () => {
    const axiosError = new Error('Bad request') as any;
    axiosError.response = { status: 400, data: { detail: 'Invalid agent' } };
    mockedAxios.isAxiosError.mockReturnValue(true);
    mockedAxios.post.mockRejectedValue(axiosError);

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

  it('should fall back to error message when axios response has no detail', async () => {
    const axiosError = new Error('Server error') as any;
    axiosError.response = { status: 500, data: {} };
    mockedAxios.isAxiosError.mockReturnValue(true);
    mockedAxios.post.mockRejectedValue(axiosError);

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.write).toHaveBeenCalledWith(
      expect.stringContaining('Server error'),
    );
    expect(res.end).toHaveBeenCalled();
  });

  it('should return 503 when a non-axios error is thrown', async () => {
    mockedAxios.isAxiosError.mockReturnValue(false);
    mockedAxios.post.mockRejectedValue(new Error('Network failure'));

    const req = buildReq({ agent_slug: 'test-agent', content: 'hello' });

    await postAgentMessageStream(req, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 503, error: 'XTM One is unreachable' });
  });
});
