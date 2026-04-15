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
import { issueAuthenticationJWT } from '../../../src/domain/user';
import { postImportDocumentAi } from '../../../src/http/httpChatbotProxy';

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
  vi.mocked(issueAuthenticationJWT).mockResolvedValue('jwt-token-123');
};

// ── Tests ──────────────────────────────────────────────────────────────────

describe('httpChatbotProxy: postImportDocumentAi', () => {
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
    const req = buildReq({ entity_id: 'e1', file_name: 'f.pdf', file_content: 'abc' });

    await postImportDocumentAi(req, res);

    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(res.json).not.toHaveBeenCalled();
  });

  it('should return 400 when chatbot CGU is not accepted', async () => {
    const fakeUser = { id: 'user-1' };
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: fakeUser } as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ filigran_chatbot_ai_cgu_status: 'disabled' } as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'pem-data' } as any);
    vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: true } as any);

    const req = buildReq({ entity_id: 'e1', file_name: 'f.pdf', file_content: 'abc' });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Chatbot is not enabled' });
  });

  it('should return 400 when license is not validated', async () => {
    const fakeUser = { id: 'user-1' };
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: fakeUser } as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ filigran_chatbot_ai_cgu_status: 'enabled' } as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: undefined } as any);
    vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: false } as any);

    const req = buildReq({ entity_id: 'e1', file_name: 'f.pdf', file_content: 'abc' });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Chatbot is not enabled' });
  });

  it('should return 400 when entity_id is missing', async () => {
    const req = buildReq({ file_name: 'f.pdf', file_content: 'abc' });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'entity_id, file_name, and file_content are required',
    });
  });

  it('should return 400 when file_name is missing', async () => {
    const req = buildReq({ entity_id: 'e1', file_content: 'abc' });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'entity_id, file_name, and file_content are required',
    });
  });

  it('should return 400 when file_content is missing', async () => {
    const req = buildReq({ entity_id: 'e1', file_name: 'f.pdf' });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'entity_id, file_name, and file_content are required',
    });
  });

  it('should return 400 when body is empty / undefined', async () => {
    const req = buildReq(undefined);

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'entity_id, file_name, and file_content are required',
    });
  });

  it('should return 400 when encoding is invalid', async () => {
    const req = buildReq({
      entity_id: 'e1',
      file_name: 'f.pdf',
      file_content: 'abc',
      encoding: 'utf-16',
    });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: "encoding must be 'text' or 'base64'" });
  });

  it('should call XTM One and return success with valid fields and default values', async () => {
    mockedAxios.post.mockResolvedValue({ data: { content: 'File imported successfully. File ID: abc-123' } });

    const req = buildReq({
      entity_id: 'entity-1',
      file_name: 'report.pdf',
      file_content: 'some text content',
    });

    await postImportDocumentAi(req, res);

    expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    const [url, rawBody, rawConfig] = mockedAxios.post.mock.calls[0];
    const body = rawBody as Record<string, any>;
    const config = rawConfig as Record<string, any>;
    expect(url).toBe('http://xtm-one/api/v1/platform/chat/messages');
    expect(body.agent_slug).toBe('opencti-assistant');
    expect(body.stream).toBe(false);
    expect(body.content).toContain('import_opencti_document_ai');
    expect(body.content).toContain('"entity_id":"entity-1"');
    expect(body.content).toContain('"file_name":"report.pdf"');
    expect(body.content).toContain('"encoding":"text"');
    expect(body.content).toContain('"mime_type":"application/octet-stream"');
    expect(config.headers.Authorization).toBe('Bearer jwt-token-123');
    expect(config.timeout).toBe(180000);

    expect(res.json).toHaveBeenCalledWith({
      status: 'success',
      content: 'File imported successfully. File ID: abc-123',
      agent_slug: 'opencti-assistant',
      tool: 'import_opencti_document_ai',
    });
  });

  it('should use custom agent_slug, encoding and mime_type when provided', async () => {
    mockedAxios.post.mockResolvedValue({ data: { content: 'Imported.' } });

    const req = buildReq({
      entity_id: 'entity-2',
      file_name: 'image.png',
      file_content: 'iVBORw0KGgo=',
      encoding: 'base64',
      mime_type: 'image/png',
      agent_slug: 'custom-agent',
    });

    await postImportDocumentAi(req, res);

    const [, rawBody] = mockedAxios.post.mock.calls[0];
    const body = rawBody as Record<string, any>;
    expect(body.agent_slug).toBe('custom-agent');
    expect(body.content).toContain('"encoding":"base64"');
    expect(body.content).toContain('"mime_type":"image/png"');

    expect(res.json).toHaveBeenCalledWith({
      status: 'success',
      content: 'Imported.',
      agent_slug: 'custom-agent',
      tool: 'import_opencti_document_ai',
    });
  });

  it('should return success with empty content when XTM One returns no content', async () => {
    mockedAxios.post.mockResolvedValue({ data: {} });

    const req = buildReq({
      entity_id: 'e1',
      file_name: 'f.txt',
      file_content: 'content',
    });

    await postImportDocumentAi(req, res);

    expect(res.json).toHaveBeenCalledWith({
      status: 'success',
      content: '',
      agent_slug: 'opencti-assistant',
      tool: 'import_opencti_document_ai',
    });
  });

  it('should return 200 with error details when axios returns an error with a response', async () => {
    const axiosError = new Error('Rate limit exceeded') as any;
    axiosError.response = { status: 429, data: { detail: 'Quota exceeded' } };
    mockedAxios.isAxiosError.mockReturnValue(true);
    mockedAxios.post.mockRejectedValue(axiosError);

    const req = buildReq({
      entity_id: 'e1',
      file_name: 'f.pdf',
      file_content: 'abc',
    });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      content: '',
      status: 'error',
      error: 'Quota exceeded',
      code: 429,
    });
  });

  it('should fall back to error message when axios response has no detail', async () => {
    const axiosError = new Error('Server error') as any;
    axiosError.response = { status: 500, data: {} };
    mockedAxios.isAxiosError.mockReturnValue(true);
    mockedAxios.post.mockRejectedValue(axiosError);

    const req = buildReq({
      entity_id: 'e1',
      file_name: 'f.pdf',
      file_content: 'abc',
    });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      content: '',
      status: 'error',
      error: 'Server error',
      code: 500,
    });
  });

  it('should return 200 with code 503 when a non-axios error is thrown', async () => {
    mockedAxios.isAxiosError.mockReturnValue(false);
    mockedAxios.post.mockRejectedValue(new Error('Network failure'));

    const req = buildReq({
      entity_id: 'e1',
      file_name: 'f.pdf',
      file_content: 'abc',
    });

    await postImportDocumentAi(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      content: '',
      status: 'error',
      error: 'Network failure',
      code: 503,
    });
  });
});
