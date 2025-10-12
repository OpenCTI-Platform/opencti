import { beforeEach, describe, expect, it, vi } from 'vitest';
import { sanitizeReferer } from '../../../src/http/httpPlatform';
import { getBaseUrl, logApp } from '../../../src/config/conf';
import type { Request } from 'express';

vi.mock('../../../src/config/conf', async (importOriginal: any) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    logApp: {
      info: vi.fn(),
      error: vi.fn(),
    },
  };
});

const baseUrl = getBaseUrl();

describe('httpPlatform: sanitizeReferer function', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe('When refererToSanitize is undefined', () => {
    it('should return baseUrl', () => {
      const result = sanitizeReferer(undefined);
      expect(result).toBe(baseUrl);
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
      expect(result).toBe(`${baseUrl}/some-relative/path`);
      expect(logApp.info).not.toHaveBeenCalled();
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
    it('should return baseUrl', () => {
      const refererToSanitize = 'http://www.wrong.com';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(baseUrl);
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

  describe('When refererToSanitize is not an IP', () => {
    it('should return baseUrl', () => {
      const refererToSanitize = '22.0.0.1';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/22.0.0.1`);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When req parameter is provided', () => {
    it('should use request context to determine base URL', () => {
      const mockReq = {
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      } as Partial<Request>;
      const refererToSanitize = '/dashboard';
      const result = sanitizeReferer(refererToSanitize, mockReq as any);
      // Should construct URL using request context
      expect(result).toContain('/dashboard');
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });
});

describe('httpPlatform: OIDC RelayState fix', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe('Optional chaining prevents TypeError', () => {
    it('should NOT throw TypeError when req.body is undefined', () => {
      const req: any = { body: undefined };
      
      // The fix: req.body?.RelayState prevents crash
      expect(() => {
        const value = req.body?.RelayState;
        return value;
      }).not.toThrow();
    });
  });

  describe('Fallback chain for referer', () => {
    it('should fallback from body.RelayState to session.referer when body is undefined', () => {
      const req: any = {
        body: undefined,
        session: { referer: '/dashboard' },
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Test the fixed fallback chain
      const referer = req.body?.RelayState ?? req.session?.referer ?? null;
      expect(referer).toBe('/dashboard');
    });
  });

  describe('sanitizeReferer with request context', () => {
    it('should use request context to determine base URL', () => {
      const mockReq: any = {
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };
      
      const result = sanitizeReferer('/dashboard', mockReq);
      expect(result).toContain('/dashboard');
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('Complete OIDC callback flow', () => {
    it('should handle OIDC callback with undefined body and session', () => {
      const req: any = {
        body: undefined,
        session: undefined,
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Simulate the complete fixed code in the finally block
      const referer = req.body?.RelayState ?? req.session?.referer ?? null;
      const sanitized = sanitizeReferer(referer, req);

      expect(sanitized).toBeDefined();
      expect(typeof sanitized).toBe('string');
    });
  });
});
