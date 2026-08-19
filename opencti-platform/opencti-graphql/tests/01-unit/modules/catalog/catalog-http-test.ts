import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockCreateAuthenticatedContext, mockDownloadFile, mockSetCookieError, mockMimeTypeFromExtension } = vi.hoisted(() => ({
  mockCreateAuthenticatedContext: vi.fn(),
  mockDownloadFile: vi.fn(),
  mockSetCookieError: vi.fn(),
  mockMimeTypeFromExtension: vi.fn(),
}));

vi.mock('../../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: mockCreateAuthenticatedContext,
}));

vi.mock('../../../../src/database/raw-file-storage', () => ({
  downloadFile: mockDownloadFile,
}));

vi.mock('../../../../src/http/httpUtils', () => ({
  setCookieError: mockSetCookieError,
}));

vi.mock('../../../../src/modules/catalog/catalog-logo-storage', () => ({
  CATALOG_CONTRACT_LOGOS_DIR: 'catalog-logos',
  getMimeTypeFromImageExtension: mockMimeTypeFromExtension,
}));

vi.mock('../../../../src/modules/catalog/catalog-logger', () => ({
  logCatalog: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import { handleCatalogLogoViewRequest } from '../../../../src/modules/catalog/catalog-http';

const buildRes = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  res.sendStatus = vi.fn().mockReturnValue(res);
  res.set = vi.fn().mockReturnValue(res);
  return res;
};

describe('catalog-http', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMimeTypeFromExtension.mockReturnValue('image/png');
  });

  it('should return 403 when unauthenticated', async () => {
    mockCreateAuthenticatedContext.mockResolvedValue({ user: null, source: 'catalog_logo_view' });
    const req = { params: { file: 'abc.png' } } as any;
    const res = buildRes();
    await handleCatalogLogoViewRequest(req, res, vi.fn());
    expect(res.sendStatus).toHaveBeenCalledWith(403);
  });

  it('should return 404 when logo does not exist', async () => {
    mockCreateAuthenticatedContext.mockResolvedValue({ user: { id: 'u1' }, source: 'catalog_logo_view' });
    mockDownloadFile.mockResolvedValue(null);
    const req = { params: { file: 'abc.png' } } as any;
    const res = buildRes();
    await handleCatalogLogoViewRequest(req, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Catalog logo not found' });
  });

  it('should stream file and set expected headers', async () => {
    const pipe = vi.fn();
    mockCreateAuthenticatedContext.mockResolvedValue({ user: { id: 'u1' }, source: 'catalog_logo_view' });
    mockDownloadFile.mockResolvedValue({ pipe });
    const req = { params: { file: 'abc.png' } } as any;
    const res = buildRes();
    await handleCatalogLogoViewRequest(req, res, vi.fn());
    expect(res.set).toHaveBeenCalledWith({ 'Content-Security-Policy': 'sandbox' });
    expect(res.set).toHaveBeenCalledWith('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    expect(res.set).toHaveBeenCalledWith({ Pragma: 'no-cache' });
    expect(res.set).toHaveBeenCalledWith('Content-type', 'image/png');
    expect(pipe).toHaveBeenCalledWith(res);
  });

  it('should handle invalid URL parameters', async () => {
    mockCreateAuthenticatedContext.mockResolvedValue({ user: { id: 'u1' }, source: 'catalog_logo_view' });
    const req = { params: {} } as any;
    const res = buildRes();
    await handleCatalogLogoViewRequest(req, res, vi.fn());
    expect(mockSetCookieError).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Invalid URL format' });
  });

  it('should handle download errors with 503', async () => {
    mockCreateAuthenticatedContext.mockResolvedValue({ user: { id: 'u1' }, source: 'catalog_logo_view' });
    mockDownloadFile.mockRejectedValue(new Error('storage failure'));
    const req = { params: { file: 'abc.png' } } as any;
    const res = buildRes();
    await handleCatalogLogoViewRequest(req, res, vi.fn());
    expect(mockSetCookieError).toHaveBeenCalledWith(res, 'storage failure');
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'storage failure' });
  });
});

