import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeOidcState, decodeOidcState, buildRateLimiterOptions, buildGraphqlUploadOptions } from '../../../src/http/httpUtils';
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

describe('httpUtils: buildGraphqlUploadOptions', () => {
  const defaultFileLimits = { maxFileSize: 1024 * 1024 * 1024, maxFiles: 20 };

  it('should apply the platform default upload file limits', () => {
    expect(buildGraphqlUploadOptions()).toEqual(defaultFileLimits);
  });

  it('should always bound the uploaded files, graphql-upload accepting any size and count by default', () => {
    const options = buildGraphqlUploadOptions();
    expect(Number.isFinite(options.maxFileSize)).toBe(true);
    expect(Number.isFinite(options.maxFiles)).toBe(true);
  });

  it('should apply the configured upload file limits', () => {
    expect(buildGraphqlUploadOptions('10mb', 5)).toEqual({ maxFileSize: 10 * 1024 * 1024, maxFiles: 5 });
    expect(buildGraphqlUploadOptions(2097152, '3')).toEqual({ maxFileSize: 2097152, maxFiles: 3 });
  });

  it('should fall back to the platform default, never to unlimited, for an invalid upload file limit', () => {
    ['not-a-size', '', 0, -1, '0mb'].forEach((size) => {
      expect(buildGraphqlUploadOptions(size).maxFileSize).toBe(defaultFileLimits.maxFileSize);
    });
    ['not-a-number', '', 0, -1, 2.5, 'Infinity'].forEach((count) => {
      expect(buildGraphqlUploadOptions('10mb', count).maxFiles).toBe(defaultFileLimits.maxFiles);
    });
  });
});
