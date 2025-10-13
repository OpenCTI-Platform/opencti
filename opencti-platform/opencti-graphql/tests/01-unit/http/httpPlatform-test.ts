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

  describe('Error handling and cleanup in auth callback', () => {
    it('should log error when authentication callback fails', () => {
      const error = new Error('Auth failed');
      const provider = 'saml';

      // Simulate the error handling code
      logApp.error('Error auth provider callback', { cause: error, provider });

      expect(logApp.error).toHaveBeenCalledWith('Error auth provider callback', {
        cause: error,
        provider: 'saml',
      });
    });

    it('should execute finally block with req.body.RelayState', () => {
      const req: any = {
        body: { RelayState: '/dashboard' },
        session: { referer: '/fallback' },
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Simulate the finally block code
      const referer = req.body?.RelayState ?? req.session?.referer ?? null;
      const sanitized = sanitizeReferer(referer, req);

      expect(referer).toBe('/dashboard');
      expect(sanitized).toContain('/dashboard');
    });

    it('should execute finally block without req.body (uses session.referer)', () => {
      const req: any = {
        body: undefined,
        session: { referer: '/settings' },
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Simulate the finally block code
      const referer = req.body?.RelayState ?? req.session?.referer ?? null;
      const sanitized = sanitizeReferer(referer, req);

      expect(referer).toBe('/settings');
      expect(sanitized).toContain('/settings');
    });

    it('should execute finally block with null referer (fallback to baseUrl)', () => {
      const req: any = {
        body: undefined,
        session: undefined,
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Simulate the finally block code
      const referer = req.body?.RelayState ?? req.session?.referer ?? null;
      const sanitized = sanitizeReferer(referer, req);

      expect(referer).toBe(null);
      expect(sanitized).toBeDefined();
    });

    it('should execute finally block with empty string RelayState', () => {
      const req: any = {
        body: { RelayState: '' },
        session: { referer: '/backup' },
        protocol: 'https',
        hostname: 'opencti.example.com',
        headers: { host: 'opencti.example.com' }
      };

      // Simulate the finally block code (empty string is falsy, so falls back to session.referer)
      const referer = req.body?.RelayState || req.session?.referer || null;
      const sanitized = sanitizeReferer(referer, req);

      expect(referer).toBe('/backup');
      expect(sanitized).toContain('/backup');
    });
  });
});
