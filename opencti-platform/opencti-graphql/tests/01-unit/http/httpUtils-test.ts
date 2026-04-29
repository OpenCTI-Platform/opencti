import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeOidcState, decodeOidcState, buildRateLimiterOptions } from '../../../src/http/httpUtils';
import * as httpConfig from '../../../src/http/httpConfig';
import { getRateProtectionIpSkipList } from '../../../src/http/httpConfig';

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
