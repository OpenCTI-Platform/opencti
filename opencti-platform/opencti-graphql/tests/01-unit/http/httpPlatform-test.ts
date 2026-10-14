import { PassThrough, Readable } from 'node:stream';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import nconf from 'nconf';
import createApp, { decodeStoragePath, sanitizeReferer, shouldIncludeHealthDetails } from '../../../src/http/httpPlatform';
import * as platformHealthMetrics from '../../../src/telemetry/platformHealthMetrics';
import { getBaseUrl, logApp } from '../../../src/config/conf';
import * as httpAuthenticatedContext from '../../../src/http/httpAuthenticatedContext';
import * as fileStorage from '../../../src/database/file-storage';
import type { LoadedFile } from '../../../src/database/file-storage';
import * as rawFileStorage from '../../../src/database/raw-file-storage';
import * as userActionListener from '../../../src/listener/UserActionListener';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

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

describe('httpPlatform: shouldIncludeHealthDetails function', () => {
  it('should include details when access key is private and query parameter is true', () => {
    expect(shouldIncludeHealthDetails('secret', 'true')).toBe(true);
  });

  it('should include details when query parameter is case-insensitive true', () => {
    expect(shouldIncludeHealthDetails('secret', 'TRUE')).toBe(true);
  });

  it('should not include details when endpoint is public', () => {
    expect(shouldIncludeHealthDetails('public', 'true')).toBe(false);
  });

  it('should not include details for any non-true query value', () => {
    expect(shouldIncludeHealthDetails('secret', '1')).toBe(false);
    expect(shouldIncludeHealthDetails('secret', 'false')).toBe(false);
    expect(shouldIncludeHealthDetails('secret', undefined)).toBe(false);
  });
});

describe('httpPlatform: /health details behavior', () => {
  const allDependenciesUp = { elasticsearch: true, storage: true, rabbitmq: true, redis: true };

  const buildResponse = () => {
    const res: any = {};
    res.set = vi.fn().mockReturnValue(res);
    res.status = vi.fn().mockReturnValue(res);
    res.send = vi.fn().mockReturnValue(res);
    return res;
  };

  const setupHealthHandler = async () => {
    const routes = new Map<string, (req: any, res: any) => Promise<void>>();
    const app: any = {
      set: vi.fn(),
      use: vi.fn(),
      get: vi.fn((path: unknown, handler: any) => {
        if (typeof path === 'string' && typeof handler === 'function') {
          routes.set(path, handler);
        }
      }),
      post: vi.fn(),
      delete: vi.fn(),
      put: vi.fn(),
      patch: vi.fn(),
      all: vi.fn(),
    };
    await createApp(app, {} as any);
    const healthRoute = Array.from(routes.entries()).find(([path]) => path.endsWith('/health'));
    return healthRoute?.[1];
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(nconf, 'get').mockImplementation((key?: string) => {
      if (key === 'app:health_access_key') {
        return 'secret';
      }
      return undefined;
    });
    vi.spyOn(platformHealthMetrics, 'getPlatformHealthStatus').mockReturnValue({ initialized: true, isHealthy: true, failures: [], dependencies: allDependenciesUp });
    vi.spyOn(platformHealthMetrics, 'getPlatformUsageMetrics').mockReturnValue({
      es_used_size: 10,
      s3_used_size: 20,
      queue_consumers: { EXTERNAL_IMPORT: 3, INTERNAL_ENRICHMENT: 2 },
    });
  });

  it('should return collected detailed metrics when details=true', async () => {
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { health_access_key: 'secret', details: 'true' } }, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({
      status: 'success',
      dependencies: allDependenciesUp,
      es_used_size: 10,
      s3_used_size: 20,
      queue_consumers: { EXTERNAL_IMPORT: 3, INTERNAL_ENRICHMENT: 2 },
    });
  });

  it('should return null detailed metrics when collection is unavailable', async () => {
    vi.spyOn(platformHealthMetrics, 'getPlatformUsageMetrics').mockReturnValue({ es_used_size: null, s3_used_size: null, queue_consumers: null });
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { health_access_key: 'secret', details: 'true' } }, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({
      status: 'success',
      dependencies: allDependenciesUp,
      es_used_size: null,
      s3_used_size: null,
      queue_consumers: null,
    });
  });

  it('should return 503 with failing dependencies without probing them', async () => {
    vi.spyOn(platformHealthMetrics, 'getPlatformHealthStatus').mockReturnValue({
      initialized: true,
      isHealthy: false,
      failures: ['redis: Redis seems down'],
      dependencies: { ...allDependenciesUp, redis: false },
    });
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { health_access_key: 'secret' } }, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'redis: Redis seems down' });
  });

  it('should name the failing dependencies on a 503 when details=true', async () => {
    vi.spyOn(platformHealthMetrics, 'getPlatformHealthStatus').mockReturnValue({
      initialized: true,
      isHealthy: false,
      failures: ['redis: Redis seems down'],
      dependencies: { ...allDependenciesUp, redis: false },
    });
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { health_access_key: 'secret', details: 'true' } }, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({
      status: 'error',
      error: 'redis: Redis seems down',
      dependencies: { elasticsearch: true, storage: true, rabbitmq: true, redis: false },
    });
  });

  it('should return 503 while the health monitor has not collected any state yet', async () => {
    vi.spyOn(platformHealthMetrics, 'getPlatformHealthStatus').mockReturnValue({
      initialized: false,
      isHealthy: false,
      failures: [],
      dependencies: { elasticsearch: false, storage: false, rabbitmq: false, redis: false },
    });
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { health_access_key: 'secret' } }, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.send).toHaveBeenCalledWith({ status: 'error', error: 'Health monitoring not initialized yet' });
  });

  it('should ignore details=true when health access is public', async () => {
    vi.spyOn(nconf, 'get').mockImplementation((key?: string) => {
      if (key === 'app:health_access_key') {
        return 'public';
      }
      return undefined;
    });
    const usageMetricsSpy = vi.spyOn(platformHealthMetrics, 'getPlatformUsageMetrics');
    const healthHandler = await setupHealthHandler();
    const res = buildResponse();

    await healthHandler?.({ query: { details: 'true' } }, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({ status: 'success' });
    expect(usageMetricsSpy).not.toHaveBeenCalled();
  });
});

interface StorageGetParams {
  file: string[];
}

interface StorageGetRequest {
  params: StorageGetParams;
}

interface StorageGetResponse extends PassThrough {
  attachment: Mock;
  cookie: Mock;
  set: Mock;
  status: Mock;
  send: Mock;
}

interface StorageGetHandler {
  (req: StorageGetRequest, res: StorageGetResponse): Promise<void>;
}

describe('httpPlatform: /storage/get behavior', () => {
  const content = Buffer.from('hello world');
  const storedFile: LoadedFile = {
    id: 'import/Report/report-id/report.pdf',
    name: 'report.pdf',
    size: content.length,
    information: '',
    lastModified: new Date(),
    lastModifiedSinceMin: 0,
    metaData: {},
    uploadStatus: 'complete',
  };

  const setupStorageGetHandler = async (): Promise<StorageGetHandler | undefined> => {
    const routes = new Map<string, StorageGetHandler>();
    const app = {
      set: vi.fn(),
      use: vi.fn(),
      get: vi.fn((path: unknown, handler: unknown) => {
        if (typeof path === 'string' && typeof handler === 'function') {
          routes.set(path, handler as StorageGetHandler);
        }
      }),
      post: vi.fn(),
      delete: vi.fn(),
      put: vi.fn(),
      patch: vi.fn(),
      all: vi.fn(),
    };
    await createApp(app as never, {} as never);
    return Array.from(routes.entries()).find(([path]) => path.endsWith('/storage/get/*file'))?.[1];
  };

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(httpAuthenticatedContext, 'createAuthenticatedContext').mockResolvedValue({ ...testContext, user: ADMIN_USER });
    vi.spyOn(fileStorage, 'loadFile').mockResolvedValue(storedFile);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue([]);
    vi.spyOn(rawFileStorage, 'downloadFileRange').mockResolvedValue({ stream: Readable.from([content]), contentLength: content.length, totalSize: content.length });
  });

  it('should send the stored object size as Content-Length, so a sync client can tell a small file from a large one', async () => {
    const storageGetHandler = await setupStorageGetHandler();
    const res: StorageGetResponse = Object.assign(new PassThrough(), { attachment: vi.fn(), cookie: vi.fn(), set: vi.fn(), status: vi.fn(), send: vi.fn() });

    await storageGetHandler?.({ params: { file: storedFile.id.split('/') } }, res);

    expect(res.set).toHaveBeenCalledWith('Content-Length', String(content.length));
    expect(res.status).not.toHaveBeenCalled();
  });
});
