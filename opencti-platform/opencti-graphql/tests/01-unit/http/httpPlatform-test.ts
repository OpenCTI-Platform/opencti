import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  decodeStoragePath,
  sanitizeReferer,
  handleStorageGet,
  handleStorageView,
  handleStorageViewEmbedded,
  handleStorageHtml,
  handleStorageEncrypted,
} from '../../../src/http/httpPlatform';
import { getBaseUrl, logApp } from '../../../src/config/conf';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));
vi.mock('../../../src/http/httpServer-draft', () => ({
  checkDraftInContext: vi.fn(),
}));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    logApp: {
      info: vi.fn(),
      error: vi.fn(),
    } };
});

const baseUrl = getBaseUrl();

describe('httpPlatform: decodeStoragePath function', () => {
  it('should decode encoded path segments containing spaces and accents', () => {
    const encodedParts = ['embedded', 'Note', 'note-id', 'Capture%20e%CC%81cran%202026-05-20%2012.34.56.png'];

    const decodedPath = decodeStoragePath(encodedParts);

    expect(decodedPath).toBe('embedded/Note/note-id/Capture écran 2026-05-20 12.34.56.png');
  });

  it('should keep invalid encoded segment unchanged', () => {
    const encodedParts = ['embedded', 'Note', 'note-id', 'broken%2Gencoding.png'];

    const decodedPath = decodeStoragePath(encodedParts);

    expect(decodedPath).toBe('embedded/Note/note-id/broken%2Gencoding.png');
  });
});

describe('httpPlatform: sanitizeReferer function', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe('When refererToSanitize is undefined', () => {
    it('should return /', () => {
      const result = sanitizeReferer(undefined);
      expect(result).toBe('/');
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize has same origin as baseUrl', () => {
    it('should return expected referer', () => {
      const refererToSanitize = `${baseUrl}/some/path`;
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(refererToSanitize);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is a relative url', () => {
    it('should return expected referer', () => {
      const refererToSanitize = '/some-relative/path';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/some-relative/path');
      expect(logApp.info).not.toHaveBeenCalled();
    });

    it('should return expected referer', () => {
      const refererToSanitize = '//my.wrong';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/');
      expect(logApp.info).toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is correct and has hash and search params', () => {
    it('should return expected referer', () => {
      const refererToSanitize = `${baseUrl}/some/path?param=value#section`;
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(refererToSanitize);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is not a correct value', () => {
    it('should return /', () => {
      const refererToSanitize = 'http://www.wrong.com';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/');
      expect(logApp.info).toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is not a domain name', () => {
    it('should return baseUrl', () => {
      const refererToSanitize = 'www.wrong.com';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/www.wrong.com`);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is an IP', () => {
    it('should return baseUrl', () => {
      const refererToSanitize = '22.0.0.1';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/22.0.0.1`);
      expect(logApp.info).not.toHaveBeenCalled();
    });

    it('should return baseUrl', () => {
      const refererToSanitize = '22.0.0.1/path/one';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/22.0.0.1/path/one`);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });
});

// ─── storage route draft-context authorization regression ───────────────────
// These routes read `context.draft_context` (set from the `opencti-draft-id`
// header) via `loadFile`, but historically only the GraphQL context enforced
// draft membership via `checkDraftInContext`. Each handler must call it and
// must abort before ever reaching `loadFile`/`downloadFile` when it rejects,
// so a caller cannot use a forged header to read a draft-scoped file they
// don't have access to.

const makeStorageReq = (params: Record<string, unknown> = {}) => ({ params, headers: {} } as any);
const makeStorageRes = () => ({
  sendStatus: vi.fn(),
  status: vi.fn().mockReturnThis(),
  send: vi.fn(),
  attachment: vi.fn(),
  set: vi.fn(),
  cookie: vi.fn(),
}) as any;

describe('storage routes: draft authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const DENIED_CONTEXT = {
    user: { id: 'user-b' },
    draft_context: 'restricted-draft',
  };
  const DRAFT_ERROR = new Error('Draft restricted-draft cannot be found');

  it('handleStorageGet refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageGet(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.attachment).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageView refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageView(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageViewEmbedded refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ 0: 'x', 1: 'entity-id', 2: 'y', 3: 'file.txt' });
    const res = makeStorageRes();

    await handleStorageViewEmbedded(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageHtml refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.md'] });
    const res = makeStorageRes();

    await handleStorageHtml(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageEncrypted refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageEncrypted(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });
});
