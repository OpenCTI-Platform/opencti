import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeOidcState, decodeOidcState, buildPublicHelmetParameters, buildDefaultHelmetParameters, buildRateLimiterOptions } from '../../../src/http/httpUtils';
import * as httpConfig from '../../../src/http/httpConfig';
import { getRateProtectionIpSkipList, getRateProtectionTimeWindowMs } from '../../../src/http/httpConfig';

describe('httpUtils: OIDC state encoding/decoding', () => {
  describe('encodeOidcState', () => {
    it('should return a non-empty base64url string', () => {
      const { state } = encodeOidcState('/dashboard');
      expect(state).toBeTruthy();
      expect(typeof state).toBe('string');
      // base64url characters only
      expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce different values each time (random nonce)', () => {
      const a = encodeOidcState('/dashboard');
      const b = encodeOidcState('/dashboard');
      expect(a).not.toBe(b);
    });
  });

  describe('decodeOidcState', () => {
    it('should round-trip a referer path', () => {
      const referer = '/dashboard/entities/malware';
      const { state } = encodeOidcState(referer);
      expect(decodeOidcState(state)?.referer).toBe(referer);
    });

    it('should round-trip a referer with query parameters', () => {
      const referer = '/dashboard?tab=overview&id=123';
      const { state } = encodeOidcState(referer);
      expect(decodeOidcState(state)?.referer).toBe(referer);
    });

    it('should return undefined for undefined input', () => {
      expect(decodeOidcState(undefined)).toBeUndefined();
    });

    it('should return undefined for empty string', () => {
      expect(decodeOidcState('')).toBeUndefined();
    });

    it('should return undefined for a random state (not our encoding)', () => {
      // A random state from another strategy would not decode to valid JSON with { r: ... }
      expect(decodeOidcState('abc123random')).toBeUndefined();
    });

    it('should return undefined when referer is empty string', () => {
      const { state } = encodeOidcState('');
      expect(decodeOidcState(state)?.referer).toBeUndefined();
    });

    it('should return undefined for malformed base64url', () => {
      expect(decodeOidcState('not!valid@base64')).toBeUndefined();
    });
  });
});

describe('buildHelmetParameters coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should most secure option works fine', () => {
    vi.spyOn(httpConfig, 'isDevMode').mockReturnValue(false);
    vi.spyOn(httpConfig, 'isUnsecureHttpResourceAllowed').mockReturnValue(false);
    vi.spyOn(httpConfig, 'getPublicAuthorizedDomainsFromConfiguration').mockReturnValue('');

    const publicHelmetParam = buildPublicHelmetParameters();
    expect(publicHelmetParam).toStrictEqual({
      contentSecurityPolicy: {
        directives: {
          connectSrc: ["'self'", 'wss://*', 'data:', 'https://*'],
          defaultSrc: ["'none'"],
          fontSrc: ["'self'", 'data:'],
          frameAncestors: "'none'",
          frameSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https://*'],
          manifestSrc: ["'self'", 'data:', 'https://*'],
          objectSrc: ["'self'", 'data:', 'https://*'],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'unsafe-url',
      },
      xFrameOptions: { action: 'deny' },
    });

    const defaultHelmetParam = buildDefaultHelmetParameters();
    expect(defaultHelmetParam).toStrictEqual({
      contentSecurityPolicy: {
        directives: {
          connectSrc: ["'self'", 'wss://*', 'data:', 'https://*'],
          defaultSrc: ["'none'"],
          fontSrc: ["'self'", 'data:'],
          frameAncestors: "'none'",
          imgSrc: ["'self'", 'data:', 'https://*'],
          manifestSrc: ["'self'", 'data:', 'https://*'],
          objectSrc: ["'self'", 'data:', 'https://*'],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'unsafe-url',
      },
      xFrameOptions: { action: 'deny' },
    });
  });

  it('should less secure options work fine', () => {
    vi.spyOn(httpConfig, 'isDevMode').mockReturnValue(true);
    vi.spyOn(httpConfig, 'isUnsecureHttpResourceAllowed').mockReturnValue(true);
    vi.spyOn(httpConfig, 'getPublicAuthorizedDomainsFromConfiguration').mockReturnValue('https://myctidomain.com');

    const publicHelmetParam = buildPublicHelmetParameters();
    expect(publicHelmetParam).toStrictEqual({
      contentSecurityPolicy: {
        directives: {
          connectSrc: ["'self'", 'wss://*', 'data:', 'https://*', 'http://*', 'ws://*'],
          defaultSrc: ["'none'"],
          fontSrc: ["'self'", 'data:'],
          frameAncestors: 'https://myctidomain.com',
          frameSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          manifestSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          objectSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'unsafe-url',
      },
      xFrameOptions: false,
    });

    const defaultHelmetParam = buildDefaultHelmetParameters();
    expect(defaultHelmetParam).toStrictEqual({
      contentSecurityPolicy: {
        directives: {
          connectSrc: ["'self'", 'wss://*', 'data:', 'https://*', 'http://*', 'ws://*'],
          defaultSrc: ["'none'"],
          fontSrc: ["'self'", 'data:'],
          frameAncestors: "'none'",
          imgSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          manifestSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          objectSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'unsafe-url',
      },
      xFrameOptions: { action: 'deny' },
    });
  });
});

describe('httpUtils: buildRateLimiter configuration tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('buildRateLimiter with default should be good', () => {
    const rateLimiter = buildRateLimiterOptions();
    expect(rateLimiter.windowMs).toBe(1000);
    expect(rateLimiter.limit).toBe(10000);
    expect(getRateProtectionIpSkipList()).toStrictEqual([]);
  });

  it('buildRateLimiter with modified configuration should be good', () => {
    vi.spyOn(httpConfig, 'getRateProtectionMaxRequests').mockReturnValue(5000);
    vi.spyOn(httpConfig, 'getRateProtectionTimeWindowMs').mockReturnValue(5);
    const rateLimiter = buildRateLimiterOptions();
    expect(rateLimiter.windowMs).toBe(5);
    expect(rateLimiter.limit).toBe(5000);
  });
});
