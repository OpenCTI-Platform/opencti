import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  applyKeepAliveTimeout,
  buildDefaultHelmetParameters,
  buildPublicHelmetParameters,
  buildRateLimiterOptions,
  clientErrorResponse,
  decodeOidcState,
  encodeOidcState,
  isClientRequestError,
  logMalformedRequest,
} from '../../../src/http/httpUtils';
import * as httpConfig from '../../../src/http/httpConfig';
import { getRateProtectionIpSkipList } from '../../../src/http/httpConfig';
import { logApp } from '../../../src/config/conf';
import { FunctionalError } from '../../../src/config/errors';
import type { Request, Response } from 'express';
import type { Server } from 'node:http';

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
          imgSrc: ["'self'", 'data:', 'blob:', 'https://*'],
          manifestSrc: ["'self'", 'data:', 'https://*'],
          objectSrc: ["'self'", 'data:', 'https://*'],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          upgradeInsecureRequests: [],
          workerSrc: ["'self'", 'blob:'],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
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
          imgSrc: ["'self'", 'data:', 'blob:', 'https://*'],
          manifestSrc: ["'self'", 'data:', 'https://*'],
          objectSrc: ["'self'", 'data:', 'https://*'],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          upgradeInsecureRequests: [],
          workerSrc: ["'self'", 'blob:'],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
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
          imgSrc: ["'self'", 'data:', 'blob:', 'https://*', 'http://*'],
          manifestSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          objectSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          upgradeInsecureRequests: null,
          workerSrc: ["'self'", 'blob:'],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
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
          imgSrc: ["'self'", 'data:', 'blob:', 'https://*', 'http://*'],
          manifestSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          objectSrc: ["'self'", 'data:', 'https://*', 'http://*'],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          upgradeInsecureRequests: null,
          workerSrc: ["'self'", 'blob:'],
        },
        useDefaults: true,
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
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

  const mockReq = (ip?: string, userAgent?: string): Partial<Request> => ({
    ip,
    headers: { 'user-agent': userAgent } as any,
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

  it('should skip exact IPs in ip_skip_list', () => {
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipList').mockReturnValue(['10.0.0.1', '10.0.0.2']);
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipRanges').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionUserAgentSkipPrefixes').mockReturnValue([]);
    const rateLimiter = buildRateLimiterOptions();
    const skip = rateLimiter.skip as (req: Partial<Request>, res: Partial<Response>) => boolean;
    expect(skip(mockReq('10.0.0.1', 'curl/7.0'), {} as Response)).toBe(true);
    expect(skip(mockReq('10.0.0.3', 'curl/7.0'), {} as Response)).toBe(false);
  });

  it('should skip IPs matching CIDR ranges in ip_skip_ranges', () => {
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipList').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipRanges').mockReturnValue(['192.168.1.0/24']);
    vi.spyOn(httpConfig, 'getRateProtectionUserAgentSkipPrefixes').mockReturnValue([]);
    const rateLimiter = buildRateLimiterOptions();
    const skip = rateLimiter.skip as (req: Partial<Request>, res: Partial<Response>) => boolean;
    expect(skip(mockReq('192.168.1.50', 'curl/7.0'), {} as Response)).toBe(true);
    expect(skip(mockReq('192.168.1.255', 'curl/7.0'), {} as Response)).toBe(true);
    expect(skip(mockReq('192.168.2.1', 'curl/7.0'), {} as Response)).toBe(false);
  });

  it('should skip requests with matching user-agent prefix', () => {
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipList').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipRanges').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionUserAgentSkipPrefixes').mockReturnValue(['Mozilla', 'MyBot']);
    const rateLimiter = buildRateLimiterOptions();
    const skip = rateLimiter.skip as (req: Partial<Request>, res: Partial<Response>) => boolean;
    expect(skip(mockReq('10.0.0.1', 'Mozilla/5.0 (Windows NT 10.0)'), {} as Response)).toBe(true);
    expect(skip(mockReq('10.0.0.1', 'mozilla/5.0'), {} as Response)).toBe(true); // case-insensitive
    expect(skip(mockReq('10.0.0.1', 'MyBot/1.0'), {} as Response)).toBe(true);
    expect(skip(mockReq('10.0.0.1', 'curl/7.0'), {} as Response)).toBe(false);
  });

  it('should not skip when ip is undefined', () => {
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipList').mockReturnValue(['10.0.0.1']);
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipRanges').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionUserAgentSkipPrefixes').mockReturnValue([]);
    const rateLimiter = buildRateLimiterOptions();
    const skip = rateLimiter.skip as (req: Partial<Request>, res: Partial<Response>) => boolean;
    expect(skip(mockReq(undefined, 'curl/7.0'), {} as Response)).toBe(false);
  });

  it('should skip via user-agent even if ip is undefined', () => {
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipList').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionIpSkipRanges').mockReturnValue([]);
    vi.spyOn(httpConfig, 'getRateProtectionUserAgentSkipPrefixes').mockReturnValue(['Mozilla']);
    const rateLimiter = buildRateLimiterOptions();
    const skip = rateLimiter.skip as (req: Partial<Request>, res: Partial<Response>) => boolean;
    // Even with no IP, user-agent prefix match should still skip
    expect(skip(mockReq(undefined, 'Mozilla/5.0'), {} as Response)).toBe(true);
  });
});

describe('httpUtils: server keep-alive timeout', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const mockServer = () => ({ keepAliveTimeout: 5000, headersTimeout: 60000 }) as Server;

  it('should apply the configured keep-alive timeout on the server', () => {
    vi.spyOn(httpConfig, 'getKeepAliveTimeout').mockReturnValue(120000);
    const server = mockServer();
    expect(applyKeepAliveTimeout(server)).toBe(120000);
    expect(server.keepAliveTimeout).toBe(120000);
  });

  it('should default above the usual 60s load balancer idle timeout', () => {
    // The node default of 5s is the root cause of the intermittent 502 behind a load balancer
    const server = mockServer();
    applyKeepAliveTimeout(server);
    expect(server.keepAliveTimeout).toBe(65000);
  });

  it('should support a disabled keep-alive timeout', () => {
    vi.spyOn(httpConfig, 'getKeepAliveTimeout').mockReturnValue(0);
    const server = mockServer();
    applyKeepAliveTimeout(server);
    expect(server.keepAliveTimeout).toBe(0);
  });

  it('should leave headersTimeout untouched', () => {
    // headersTimeout only bounds the headers of a request already started, it never counts
    // keep-alive idle time, so it has no constraint against keepAliveTimeout.
    vi.spyOn(httpConfig, 'getKeepAliveTimeout').mockReturnValue(120000);
    const server = mockServer();
    applyKeepAliveTimeout(server);
    expect(server.headersTimeout).toBe(60000);
  });
});

// The shapes below are the ones actually produced at runtime, reproduced here because the cases
// they stand for cannot be provoked over http in the integration test: a 413 needs a body above the
// configured limit, a 499 needs the client to vanish mid-upload, and a session caller needs a
// cookie the test client does not hold.
const uploadError = () => Object.assign(new Error('Missing multipart field \u2018operations\u2019 (https://github.com/jaydenseric/graphql-multipart-request-spec).'), {
  name: 'BadRequestError',
  status: 400,
  statusCode: 400,
  expose: true,
});

// The express router sets a status and nothing else - no statusCode, no expose.
const paramDecodeError = () => Object.assign(new URIError("Failed to decode param '.env%c0%ae'"), {
  status: 400,
});

// body-parser hands its own errors to http-errors, which adds status, statusCode and expose, and
// copies the raw request body onto the error.
const bodyParseError = () => Object.assign(new SyntaxError('Unexpected end of JSON input'), {
  name: 'SyntaxError',
  status: 400,
  statusCode: 400,
  expose: true,
  type: 'entity.parse.failed',
  body: '{"query":"mutation { login(password: \\"hunter2\\") }"',
});

const mockRequest = (overrides: Record<string, any> = {}) => ({
  method: 'POST',
  originalUrl: '/graphql',
  url: '/graphql',
  ip: '10.0.0.1',
  headers: {},
  ...overrides,
} as unknown as Request);

describe('httpUtils: isClientRequestError', () => {
  it('should accept an http-errors 4xx, as graphql-upload and body-parser build them', () => {
    expect(isClientRequestError(uploadError())).toBe(true);
    expect(isClientRequestError(bodyParseError())).toBe(true);
  });

  it('should accept a router param decoding error, which carries a status but no expose', () => {
    expect(isClientRequestError(paramDecodeError())).toBe(true);
  });

  it('should accept the 4xx that cannot be provoked over http', () => {
    // graphql-upload field size limit / body-parser entity.too.large
    expect(isClientRequestError({ status: 413, expose: true })).toBe(true);
    // graphql-upload, client gone during the upload stream parse
    expect(isClientRequestError({ status: 499, expose: true })).toBe(true);
  });

  it('should fall back to statusCode when status is absent', () => {
    expect(isClientRequestError({ statusCode: 415 })).toBe(true);
  });

  it('should reject a 5xx, so platform failures keep their error level and their 500', () => {
    expect(isClientRequestError({ status: 500, expose: false })).toBe(false);
    expect(isClientRequestError({ status: 503 })).toBe(false);
  });

  it('should reject an error with no usable status', () => {
    expect(isClientRequestError(new Error('boom'))).toBe(false);
    expect(isClientRequestError({ status: '400' })).toBe(false);
    expect(isClientRequestError(undefined)).toBe(false);
    expect(isClientRequestError(null)).toBe(false);
  });

  it('should reject an opencti domain error, which carries http_status in its extensions only', () => {
    // This is what makes it safe to key on the status alone rather than on expose.
    expect(isClientRequestError(FunctionalError('Business validation'))).toBe(false);
  });
});

describe('httpUtils: clientErrorResponse', () => {
  it('should relay a graphql-upload message that is a pure constant, spec link included', () => {
    const { status, body } = clientErrorResponse(uploadError());
    expect(status).toBe(400);
    expect(body.error).toBe(uploadError().message);
    expect(body.error).toContain('graphql-multipart-request-spec');
  });

  it('should not relay the graphql-upload messages that interpolate caller input', () => {
    // The four below embed a multipart field name, a map key or an object path.
    const interpolated = [
      'The \u2018<script>\u2019 multipart field value exceeds the 1000000 byte size limit.',
      'Invalid type for the \u2018map\u2019 multipart field entry key \u2018<script>\u2019 array (https://github.com/jaydenseric/graphql-multipart-request-spec).',
      'Invalid type for the \u2018map\u2019 multipart field entry key \u2018<script>\u2019 array index \u20180\u2019 value (https://github.com/jaydenseric/graphql-multipart-request-spec).',
      'Invalid object path for the \u2018map\u2019 multipart field entry key \u2018<script>\u2019 array index \u20180\u2019 value \u2018variables.<script>\u2019 (https://github.com/jaydenseric/graphql-multipart-request-spec).',
    ];

    interpolated.forEach((message) => {
      const { body } = clientErrorResponse(Object.assign(new Error(message), { status: 400, expose: true }));
      expect(body.error).toBe('Bad request');
      expect(body.error).not.toContain('<script>');
    });
  });

  it('should fall back to the built message when graphql-upload rewords one', () => {
    // A version bump degrades to the generic answer rather than relaying an unreviewed string.
    const reworded = Object.assign(new Error('Missing multipart field "operations".'), { status: 400, expose: true });
    expect(clientErrorResponse(reworded).body.error).toBe('Bad request');
  });

  it('should not quote back a router error message, which embeds the probed path', () => {
    const { status, body } = clientErrorResponse(paramDecodeError());
    expect(status).toBe(400);
    expect(body.error).toBe('Bad request');
    expect(JSON.stringify(body)).not.toContain('.env');
  });

  it('should not quote back a json parse message, which embeds a snippet of the body', () => {
    const { status, body } = clientErrorResponse(bodyParseError());
    expect(status).toBe(400);
    expect(body.error).toBe('Invalid json in request body');
    expect(JSON.stringify(body)).not.toContain('hunter2');
  });

  it('should name the parser failure when the error type is known', () => {
    expect(clientErrorResponse({ status: 413, type: 'entity.too.large' }).body.error).toBe('Request body too large');
    expect(clientErrorResponse({ status: 415, type: 'charset.unsupported' }).body.error).toBe('Unsupported charset');
    expect(clientErrorResponse({ status: 415, type: 'encoding.unsupported' }).body.error).toBe('Unsupported content encoding');
  });

  it('should fall back to the status, then to a bad request, for an untyped error', () => {
    expect(clientErrorResponse({ status: 413 }).body.error).toBe('Payload too large');
    expect(clientErrorResponse({ status: 499 }).body.error).toBe('Client closed request');
    expect(clientErrorResponse({ status: 418 }).body.error).toBe('Bad request');
  });

  it('should ignore expose entirely', () => {
    const exposed = clientErrorResponse({ status: 400, expose: true, message: 'leak' });
    const notExposed = clientErrorResponse({ status: 400, expose: false, message: 'leak' });
    expect(exposed.body).toEqual(notExposed.body);
    expect(exposed.body.error).toBe('Bad request');
  });

  it('should resolve the status from status, then statusCode, then default to 400', () => {
    expect(clientErrorResponse({ status: 413 }).status).toBe(413);
    expect(clientErrorResponse({ statusCode: 415 }).status).toBe(415);
    expect(clientErrorResponse(new Error('no status')).status).toBe(400);
  });
});

describe('httpUtils: logMalformedRequest', () => {
  let infoSpy: any;

  beforeEach(() => {
    infoSpy = vi.spyOn(logApp, 'info').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const loggedMeta = () => infoSpy.mock.calls[0][1];

  it('should log at info level, never as a platform error', () => {
    const errorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    logMalformedRequest(mockRequest(), uploadError());
    expect(infoSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should default to the http message and accept a caller supplied one', () => {
    logMalformedRequest(mockRequest(), uploadError());
    expect(infoSpy.mock.calls[0][0]).toBe('Malformed http request call');
    logMalformedRequest(mockRequest(), uploadError(), 'Malformed graphql request call');
    expect(infoSpy.mock.calls[1][0]).toBe('Malformed graphql request call');
  });

  it('should carry the error identity and the request shape', () => {
    logMalformedRequest(mockRequest({
      method: 'POST',
      originalUrl: '/graphql',
      headers: { 'content-type': 'multipart/form-data', 'content-length': '512', 'user-agent': 'python-requests/2.31.0' },
    }), bodyParseError());

    expect(loggedMeta()).toMatchObject({
      reason: 'Unexpected end of JSON input',
      errorName: 'SyntaxError',
      errorType: 'entity.parse.failed',
      status: 400,
      method: 'POST',
      path: '/graphql',
      userAgent: 'python-requests/2.31.0',
      ip: '10.0.0.1',
      contentType: 'multipart/form-data',
      contentLength: '512',
    });
  });

  it('should report the scheme of a token caller, never the token', () => {
    logMalformedRequest(mockRequest({ headers: { authorization: 'Bearer 2b4f1c9e-super-secret-token' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('Bearer');
    expect(loggedMeta().userId).toBeUndefined();
    expect(JSON.stringify(loggedMeta())).not.toContain('super-secret-token');
  });

  it('should report an unparsable authorization header as unknown, never as its own content', () => {
    // A malformed client can send a raw credential with no separating space.
    logMalformedRequest(mockRequest({ headers: { authorization: 'flgrn_octi_tkn_2b4f1c9e' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('unknown');
    expect(JSON.stringify(loggedMeta())).not.toContain('flgrn_octi_tkn');
  });

  it('should report an unsupported scheme as unknown', () => {
    logMalformedRequest(mockRequest({ headers: { authorization: 'Digest username="admin", response="deadbeef"' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('unknown');
    expect(JSON.stringify(loggedMeta())).not.toContain('deadbeef');
  });

  it('should normalize the scheme case, since it is case insensitive on the wire', () => {
    logMalformedRequest(mockRequest({ headers: { authorization: 'bearer 2b4f1c9e-super-secret-token' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('Bearer');
  });

  it('should report a basic auth caller by its scheme', () => {
    logMalformedRequest(mockRequest({ headers: { authorization: 'Basic dXNlcjpwYXNz' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('Basic');
    expect(JSON.stringify(loggedMeta())).not.toContain('dXNlcjpwYXNz');
  });

  it('should report a session caller as session, with its user id', () => {
    logMalformedRequest(mockRequest({ session: { user: { id: 'user-id-1' } } }), uploadError());

    expect(loggedMeta().authScheme).toBe('session');
    expect(loggedMeta().userId).toBe('user-id-1');
  });

  it('should report an anonymous caller explicitly rather than leaving the field out', () => {
    logMalformedRequest(mockRequest(), uploadError());

    // An absent authScheme would then mean a bug in the helper, not an anonymous caller.
    expect(loggedMeta().authScheme).toBe('unauthenticated');
    expect('authScheme' in loggedMeta()).toBe(true);
  });

  it('should treat an empty authorization header as no credential at all', () => {
    logMalformedRequest(mockRequest({ headers: { authorization: '' } }), uploadError());

    expect(loggedMeta().authScheme).toBe('unauthenticated');
  });

  it('should carry the opencti job headers, which name a connector caller', () => {
    logMalformedRequest(mockRequest({
      headers: { 'opencti-work-id': 'work--123', 'opencti-draft-id': 'draft--456' },
    }), uploadError());

    expect(loggedMeta()).toMatchObject({ workId: 'work--123', draftId: 'draft--456' });
  });

  it('should carry the forwarded address, since req.ip is the proxy behind an untrusted one', () => {
    logMalformedRequest(mockRequest({ ip: '10.0.0.254', headers: { 'x-forwarded-for': '203.0.113.7' } }), uploadError());

    expect(loggedMeta()).toMatchObject({ ip: '10.0.0.254', forwardedFor: '203.0.113.7' });
  });

  it('should log the pathname only, never the query string', () => {
    // The platform accepts credentials in the query string, so originalUrl must not be logged raw.
    logMalformedRequest(mockRequest({
      method: 'GET',
      originalUrl: '/health?health_access_key=super-secret-key&details=true',
      headers: { referer: 'https://opencti.example/auth/oidc/callback?code=auth-code-1&state=xyz' },
    }), paramDecodeError());

    expect(loggedMeta().path).toBe('/health');
    expect(loggedMeta().referer).toBe('https://opencti.example/auth/oidc/callback');
    const serialized = JSON.stringify(loggedMeta());
    expect(serialized).not.toContain('super-secret-key');
    expect(serialized).not.toContain('auth-code-1');
  });

  it('should fall back to req.url when originalUrl is absent, still without the query string', () => {
    logMalformedRequest(mockRequest({ originalUrl: undefined, url: '/graphql?debug=1' }), uploadError());

    expect(loggedMeta().path).toBe('/graphql');
  });

  it('should never log the raw body that body-parser attaches to a parse error', () => {
    logMalformedRequest(mockRequest(), bodyParseError());

    expect(JSON.stringify(loggedMeta())).not.toContain('hunter2');
    expect(loggedMeta().body).toBeUndefined();
  });
});
