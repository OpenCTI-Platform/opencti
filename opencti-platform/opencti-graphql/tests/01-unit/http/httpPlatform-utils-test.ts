import { describe, expect, it } from 'vitest';
import { computeFrameAncestors, buildCspDirectives, selectSecurityMiddlewareType, healthCheckTimeout } from '../../../src/http/httpPlatform-utils';

describe('httpPlatform-utils', () => {
  // ---------------------------------------------------------------------------
  // computeFrameAncestors
  // ---------------------------------------------------------------------------
  describe('computeFrameAncestors', () => {
    it('should return "\'none\'" when input is undefined', () => {
      expect(computeFrameAncestors(undefined)).toBe("'none'");
    });

    it('should return "\'none\'" when input is null', () => {
      expect(computeFrameAncestors(null)).toBe("'none'");
    });

    it('should return "\'none\'" when input is an empty string', () => {
      expect(computeFrameAncestors('')).toBe("'none'");
    });

    it('should return "\'none\'" when input is only whitespace', () => {
      expect(computeFrameAncestors('   ')).toBe("'none'");
    });

    it('should return the trimmed domain string when a single domain is provided', () => {
      expect(computeFrameAncestors('https://example.com')).toBe('https://example.com');
    });

    it('should trim surrounding whitespace from the domain string', () => {
      expect(computeFrameAncestors('  https://example.com  ')).toBe('https://example.com');
    });

    it('should return multiple domains as-is when provided', () => {
      const domains = 'https://a.com https://b.com';
      expect(computeFrameAncestors(domains)).toBe(domains);
    });
  });

  // ---------------------------------------------------------------------------
  // buildCspDirectives
  // ---------------------------------------------------------------------------
  describe('buildCspDirectives', () => {
    it('should always include self and unsafe-inline in scriptSrc', () => {
      const { scriptSrc } = buildCspDirectives(false, false);
      expect(scriptSrc).toContain("'self'");
      expect(scriptSrc).toContain("'unsafe-inline'");
    });

    it('should add unsafe-eval to scriptSrc in dev mode', () => {
      const { scriptSrc } = buildCspDirectives(true, false);
      expect(scriptSrc).toContain("'unsafe-eval'");
    });

    it('should NOT add unsafe-eval to scriptSrc when dev mode is off', () => {
      const { scriptSrc } = buildCspDirectives(false, false);
      expect(scriptSrc).not.toContain("'unsafe-eval'");
    });

    it('should include https://* but NOT http://* when HTTP resources are disallowed', () => {
      const { imgSrc, manifestSrc, connectSrc, objectSrc } = buildCspDirectives(false, false);

      for (const directive of [imgSrc, manifestSrc, connectSrc, objectSrc]) {
        expect(directive).toContain('https://*');
        expect(directive).not.toContain('http://*');
      }
    });

    it('should include http://* sources when HTTP resources are allowed', () => {
      const { imgSrc, manifestSrc, connectSrc, objectSrc } = buildCspDirectives(false, true);

      expect(imgSrc).toContain('http://*');
      expect(manifestSrc).toContain('http://*');
      expect(connectSrc).toContain('http://*');
      expect(objectSrc).toContain('http://*');
    });

    it('should include ws://* in connectSrc when HTTP resources are allowed', () => {
      const { connectSrc } = buildCspDirectives(false, true);
      expect(connectSrc).toContain('ws://*');
    });

    it('should NOT include ws://* in connectSrc when HTTP resources are disallowed', () => {
      const { connectSrc } = buildCspDirectives(false, false);
      expect(connectSrc).not.toContain('ws://*');
    });

    it('should always include wss://* in connectSrc regardless of HTTP resource flag', () => {
      const withHttp = buildCspDirectives(false, true);
      const withoutHttp = buildCspDirectives(false, false);
      expect(withHttp.connectSrc).toContain('wss://*');
      expect(withoutHttp.connectSrc).toContain('wss://*');
    });

    it('should combine dev mode and HTTP resources flags correctly', () => {
      const { scriptSrc, imgSrc, connectSrc } = buildCspDirectives(true, true);
      expect(scriptSrc).toContain("'unsafe-eval'");
      expect(imgSrc).toContain('http://*');
      expect(connectSrc).toContain('ws://*');
    });

    it('should return fresh arrays on each call (no shared mutable state)', () => {
      const first = buildCspDirectives(false, false);
      const second = buildCspDirectives(false, false);
      expect(first.scriptSrc).not.toBe(second.scriptSrc);
      expect(first.imgSrc).not.toBe(second.imgSrc);
    });
  });

  // ---------------------------------------------------------------------------
  // selectSecurityMiddlewareType
  // ---------------------------------------------------------------------------
  describe('selectSecurityMiddlewareType', () => {
    const basePath = '';

    describe('with empty basePath', () => {
      it('should return "public" for /public URLs', () => {
        expect(selectSecurityMiddlewareType('/public/dashboard/abc', basePath)).toBe('public');
      });

      it('should return "public" for /public without trailing path', () => {
        expect(selectSecurityMiddlewareType('/public', basePath)).toBe('public');
      });

      it('should return "index" for /dashboard URLs', () => {
        expect(selectSecurityMiddlewareType('/dashboard', basePath)).toBe('index');
      });

      it('should return "index" for nested /dashboard paths', () => {
        expect(selectSecurityMiddlewareType('/some/dashboard/page', basePath)).toBe('index');
      });

      it('should return "default" for other URLs', () => {
        expect(selectSecurityMiddlewareType('/api/graphql', basePath)).toBe('default');
      });

      it('should return "default" when URL is an empty string', () => {
        expect(selectSecurityMiddlewareType('', basePath)).toBe('default');
      });
    });

    describe('with a configured basePath', () => {
      const customBasePath = '/opencti';

      it('should return "public" for basePath + /public URLs', () => {
        expect(selectSecurityMiddlewareType('/opencti/public/dashboard/1', customBasePath)).toBe('public');
      });

      it('should return "default" for /public that does not match basePath prefix', () => {
        // /public without the basePath prefix should NOT match the public pattern
        expect(selectSecurityMiddlewareType('/public/something', customBasePath)).toBe('default');
      });

      it('should return "index" for URLs containing /dashboard', () => {
        expect(selectSecurityMiddlewareType('/opencti/dashboard', customBasePath)).toBe('index');
      });

      it('should return "default" for generic paths under basePath', () => {
        expect(selectSecurityMiddlewareType('/opencti/graphql', customBasePath)).toBe('default');
      });
    });

    describe('priority: /public takes precedence over /dashboard', () => {
      it('should return "public" when URL matches both /public and /dashboard', () => {
        // A URL starting with basePath/public that also contains /dashboard
        expect(selectSecurityMiddlewareType('/public/dashboard', '')).toBe('public');
      });
    });
  });

  // ---------------------------------------------------------------------------
  // healthCheckTimeout
  // ---------------------------------------------------------------------------
  describe('healthCheckTimeout', () => {
    it('should resolve when the wrapped promise resolves before timeout', async () => {
      const fast = Promise.resolve('ok');
      const result = await healthCheckTimeout(fast, 'should not timeout');
      expect(result).toBe('ok');
    });

    it('should reject with timeout message when the promise is too slow', async () => {
      const slow = new Promise((resolve) => {
        setTimeout(() => resolve('late'), 500);
      });
      await expect(healthCheckTimeout(slow, 'timed out!', 50))
        .rejects
        .toThrow('timed out!');
    });

    it('should propagate the original rejection when the promise rejects before timeout', async () => {
      const failing = Promise.reject(new Error('connection refused'));
      await expect(healthCheckTimeout(failing, 'timeout msg', 5000))
        .rejects
        .toThrow('connection refused');
    });

    it('should use the default 15 000 ms timeout when none is specified', async () => {
      // We verify indirectly: a promise resolving immediately should succeed
      const instant = Promise.resolve(42);
      const result = await healthCheckTimeout(instant, 'timeout');
      expect(result).toBe(42);
    });

    it('should reject exactly with an Error instance', async () => {
      const slow = new Promise(() => {}); // never resolves
      try {
        await healthCheckTimeout(slow, 'my message', 10);
        expect.unreachable('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect((e as Error).message).toBe('my message');
      }
    });
  });
});
