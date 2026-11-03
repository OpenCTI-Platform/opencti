import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as conf from '../../../src/config/conf';
import createApp, { decodeStoragePath } from '../../../src/http/httpPlatform';
import { sanitizeReferer } from '../../../src/http/httpUtils';
import { getBaseUrl, logApp } from '../../../src/config/conf';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual:object = await importOriginal();
  return {
    ...actual,
    logApp: {
      info: vi.fn(),
      error: vi.fn(),
    }, };
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

  describe('When base url is not configured', () => {
    const req = { protocol: 'https', hostname: 'cti.example.com', headers: { host: 'cti.example.com' } } as any;

    beforeEach(() => {
      vi.spyOn(conf, 'getBaseUrl').mockImplementation((request?: any) => (request ? 'https://cti.example.com' : ''));
    });

    it('should infer the platform origin from the request', () => {
      expect(sanitizeReferer('/some/path', req)).toBe('/some/path');
    });

    it('should reject a double slash referer', () => {
      expect(sanitizeReferer('//evil.example/phish', req)).toBe('/');
    });

    it('should return / instead of throwing without request', () => {
      expect(sanitizeReferer('/some/path')).toBe('/');
    });
  });

  describe('When base url is set without scheme', () => {
    it('should return / instead of throwing', () => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('cti.example.com');
      expect(sanitizeReferer('/some/path')).toBe('/');
    });
  });

  describe('When base url has an uppercase host and a default port', () => {
    it('should accept a referer on the same origin', () => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('https://CTI.example.com:443');
      expect(sanitizeReferer('https://cti.example.com/some/path')).toBe('https://cti.example.com/some/path');
    });
  });

  describe('When base url has a base path', () => {
    beforeEach(() => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('https://cti.example.com/opencti');
    });

    it('should keep the query string of a referer on the base path root', () => {
      expect(sanitizeReferer('/opencti?tab=1')).toBe('/opencti?tab=1');
    });

    it('should keep the hash of a referer on the base path root', () => {
      expect(sanitizeReferer('/opencti#section')).toBe('/opencti#section');
    });

    it('should reject a referer outside the base path that shares its prefix', () => {
      expect(sanitizeReferer('https://cti.example.com/opencti-evil')).toBe('/');
    });
  });
});

describe('httpPlatform: /logout redirect', () => {
  const setupLogoutHandler = async () => {
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
    const logoutRoute = Array.from(routes.entries()).find(([path]) => path.endsWith('/logout'));
    return logoutRoute?.[1];
  };

  it('should keep logout redirect on the platform origin when referer path starts with a double slash', async () => {
    const logoutHandler = await setupLogoutHandler();
    const res: any = { redirect: vi.fn(), cookie: vi.fn() };

    await logoutHandler?.({ headers: { referer: 'https://attacker.com//evil.example/phish' }, session: {} }, res);

    expect(res.redirect).toHaveBeenCalledTimes(1);
    const target = res.redirect.mock.calls[0][0];
    expect(new URL(target, baseUrl).origin).toBe(new URL(baseUrl).origin);
  });
});
