import type { Request, Response } from 'express';
import type { AuthContext } from '../types/user';
import crypto from 'node:crypto';
import { booleanConf, logApp } from '../config/conf';
import { isEmptyField } from '../database/utils';
import { URL } from 'node:url';
import {
  getKeepAliveTimeout,
  getPublicAuthorizedDomainsFromConfiguration,
  getRateProtectionIpSkipList,
  getRateProtectionIpSkipRanges,
  getRateProtectionMaxRequests,
  getRateProtectionTimeWindowMs,
  getRateProtectionUserAgentSkipPrefixes,
  isDevMode,
  isUnsecureHttpResourceAllowed,
} from './httpConfig';
import type { HelmetOptions } from 'helmet';
import { type Options, ipKeyGenerator } from 'express-rate-limit';
import { BlockList } from 'node:net';
import type { Server } from 'node:http';

export const setCookieError = (res: Response, message: string) => {
  // Map error messages to safe, non-sensitive codes exposed to the client.
  const normalized = (message || '').toLowerCase();
  let flashCode: string;
  if (normalized.includes('ip address is not allowed')) {
    flashCode = 'IP_NOT_ALLOWED';
  } else if (normalized.includes('authentication is not available') || normalized.includes('authentication strategy is not available')) {
    flashCode = 'PROVIDER_NOT_AVAILABLE';
  } else if (normalized.includes('enterprise edition')) {
    flashCode = 'ENTERPRISE_EDITION_REQUIRED';
  } else {
    flashCode = 'AUTH_ERROR';
  }
  res.cookie('opencti_flash', flashCode, {
    maxAge: 10000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
    sameSite: 'strict',
  });
};

export const extractRefererPathFromReq = (req: Request) => {
  if (!req.headers.referer || isEmptyField(req.headers.referer)) {
    return undefined;
  }

  try {
    const refererUrl = new URL(req.headers.referer);
    // Keep only the pathname and search to prevent OPEN REDIRECT CWE-601
    return refererUrl.pathname + refererUrl.search;
  } catch {
    // prevent any invalid referer
    logApp.warn('Invalid referer for redirect extraction', { referer: req.headers.referer });
  }
};

// Whether this request is driven by a signed-in person in a browser, as opposed
// to an API token.
//
// `context.user_with_session` alone does not answer that: it only records that
// a session cookie was present, while `authenticateUserFromRequest` returns on
// the bearer-token branch before it ever looks at the session (`domain/user.js`).
// A request carrying a token *and* any user's cookie therefore authenticates as
// the token identity while still looking session-backed. Require that the
// identity actually resolved from the session, by matching it against the
// session user and refusing any request that presents an Authorization header
// at all.
export const isBrowserSessionRequest = (req: Request, context: AuthContext): boolean => {
  if (req.headers.authorization) return false;
  if (!context.user_with_session) return false;
  const sessionUserId = req.session?.user?.id;
  return !!sessionUserId && sessionUserId === context.user?.id;
};

/**
 * Encode a referer path into an OIDC-safe state parameter.
 * The state contains a random nonce (for unpredictability) and the referer.
 * This parallels SAML's RelayState mechanism for relaying application state
 * through the authentication flow.
 */
export const encodeOidcState = (referer: string) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = JSON.stringify({ n: nonce, r: referer });
  return { nonce, state: Buffer.from(payload).toString('base64url') };
};

/**
 * Decode a referer path from an OIDC state parameter.
 * Returns undefined if the state is not a valid encoded referer
 * (e.g. a random state from a different strategy or a corrupted value).
 */
export const decodeOidcState = (state: string | undefined) => {
  if (!state) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
    const r = payload?.r;
    const n = payload?.n;
    const referer = typeof r === 'string' && r.length > 0 ? r : undefined;
    const nonce = typeof n === 'string' && n.length > 0 ? n : undefined;
    return { referer, nonce };
  } catch {
    return undefined;
  }
};

// Region helmet configuration

const buildScriptSrc = () => {
  const scriptSrc = ["'self'", "'unsafe-inline'"];
  if (isDevMode()) {
    scriptSrc.push("'unsafe-eval'");
  }
  return scriptSrc;
};

const buildImgSrcSrc = () => {
  const imgSrc = ["'self'", 'data:', 'blob:', 'https://*'];
  if (isUnsecureHttpResourceAllowed()) {
    imgSrc.push('http://*');
  }
  return imgSrc;
};

const buildManifestSrc = () => {
  const manifestSrc = ["'self'", 'data:', 'https://*'];
  if (isUnsecureHttpResourceAllowed()) {
    manifestSrc.push('http://*');
  }
  return manifestSrc;
};

const buildConnectSrc = () => {
  const connectSrc = ["'self'", 'wss://*', 'data:', 'https://*'];
  if (isUnsecureHttpResourceAllowed()) {
    connectSrc.push('http://*');
    connectSrc.push('ws://*');
  }
  return connectSrc;
};

const buildObjectSrc = () => {
  const objectSrc = ["'self'", 'data:', 'https://*'];
  if (isUnsecureHttpResourceAllowed()) {
    objectSrc.push('http://*');
  }
  return objectSrc;
};

export const buildPublicHelmetParameters = (): HelmetOptions => {
  const ancestorsFromConfig = getPublicAuthorizedDomainsFromConfiguration();
  const frameAncestorDomains = ancestorsFromConfig === '' ? "'none'" : ancestorsFromConfig;
  const allowedFrameSrc = ["'self'"];
  const helmetConfiguration: HelmetOptions = {
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: buildScriptSrc(),
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'none'"],
        fontSrc: ["'self'", 'data:'],
        imgSrc: buildImgSrcSrc(),
        manifestSrc: buildManifestSrc(),
        connectSrc: buildConnectSrc(),
        objectSrc: buildObjectSrc(),
        workerSrc: ["'self'", 'blob:'],
        frameSrc: allowedFrameSrc,
        frameAncestors: frameAncestorDomains,
        upgradeInsecureRequests: isUnsecureHttpResourceAllowed() ? null : [],
      },
    },
    // false means disable the header when frame-ancestors allows external domains
    xFrameOptions: frameAncestorDomains === "'none'" ? { action: 'deny' } : false,
  };
  return helmetConfiguration;
};

export const buildDefaultHelmetParameters = (): HelmetOptions => {
  const helmetConfiguration: HelmetOptions = {
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: buildScriptSrc(),
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'none'"],
        fontSrc: ["'self'", 'data:'],
        imgSrc: buildImgSrcSrc(),
        manifestSrc: buildManifestSrc(),
        connectSrc: buildConnectSrc(),
        objectSrc: buildObjectSrc(),
        workerSrc: ["'self'", 'blob:'],
        frameAncestors: "'none'",
        upgradeInsecureRequests: isUnsecureHttpResourceAllowed() ? null : [],
      },
    },
    xFrameOptions: { action: 'deny' },
  };
  return helmetConfiguration;
};

/**
 * Generate a rate-limit key combining IP and User-Agent.
 * This allows to distinguish different users behind a shared IP.
 */
const buildRateLimitKey = (req: Request): string => {
  const ip = ipKeyGenerator(req.ip ?? 'unknown');
  const userAgent = req.headers['user-agent'] ?? 'unknown';
  return crypto.createHash('sha256').update(`${ip}|${userAgent}`).digest('hex');
};

/**
 * Build a BlockList from CIDR ranges for efficient IP range matching.
 */
const buildIpRangeSkipList = (ranges: string[]): BlockList => {
  const blockList = new BlockList();
  for (const range of ranges) {
    try {
      if (range.includes('/')) {
        const [subnet, prefixStr] = range.split('/');
        const prefix = parseInt(prefixStr, 10);
        const type = subnet.includes(':') ? 'ipv6' : 'ipv4';
        blockList.addSubnet(subnet, prefix, type);
      } else {
        // Single IP provided as a "range" entry — treat as exact match
        const type = range.includes(':') ? 'ipv6' : 'ipv4';
        blockList.addAddress(range, type);
      }
    } catch (e: any) {
      logApp.warn('[HTTP] Error when building the IP range that should be ignored by the rate limit, please verify your configuration.', e);
    }
  }

  return blockList;
};

/**
 * Check whether a User-Agent header matches any of the configured skip prefixes.
 */
const matchesUserAgentSkipPrefix = (userAgent: string | undefined, prefixes: string[]): boolean => {
  if (!userAgent || prefixes.length === 0) return false;
  const lowerUA = userAgent.toLowerCase();
  return prefixes.some((prefix) => lowerUA.startsWith(prefix.toLowerCase()));
};

// Throttle map: tracks last log timestamp per IP+UA pair to avoid log flooding.
// Key = "ip|userAgent", value = last log epoch ms.
const rateLimitLogThrottle = new Map<string, number>();
const RATE_LIMIT_LOG_INTERVAL_MS = 60_000; // 1 minute
const MAX_LOG_RATE_ENTRIES = 100;
/**
 * Log a rate-limit event for an IP + User-Agent pair at most once per minute.
 */
const logRateLimitThrottled = (ip: string, userAgent: string): void => {
  const key = `${ip}|${userAgent}`;
  const now = Date.now();
  const lastLogged = rateLimitLogThrottle.get(key);
  if (lastLogged === undefined || now - lastLogged >= RATE_LIMIT_LOG_INTERVAL_MS) {
    rateLimitLogThrottle.set(key, now);
    logApp.warn('[RATE-LIMIT] Rate limited request', { ip, userAgent });
    if (rateLimitLogThrottle.size > MAX_LOG_RATE_ENTRIES) {
      for (const [k, v] of rateLimitLogThrottle) {
        if (now - v >= RATE_LIMIT_LOG_INTERVAL_MS) rateLimitLogThrottle.delete(k);
      }
    }
  }
};

export const buildRateLimiterOptions = (): Options => {
  const skipList: string[] = getRateProtectionIpSkipList();
  const skipRanges: string[] = getRateProtectionIpSkipRanges();
  const userAgentSkipPrefixes: string[] = getRateProtectionUserAgentSkipPrefixes();
  const ipRangeSkipList = buildIpRangeSkipList(skipRanges);

  // There is 2 ways to exclude IP from rate limit: by exact IP or by ranges.
  const isIpInSkipList = (ip: string): boolean => {
    if (skipList.includes(ip)) return true;
    return skipRanges.length > 0 && ipRangeSkipList.check(ip);
  };

  const rateLimitOptions: Partial<Options> = {
    windowMs: getRateProtectionTimeWindowMs(),
    limit: getRateProtectionMaxRequests(),
    keyGenerator: buildRateLimitKey,
    handler: (req, res /* , next */) => {
      const ip = req.ip ?? 'unknown';
      const userAgent = req.headers['user-agent'] ?? 'unknown';
      logRateLimitThrottled(ip, userAgent);
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
    skip: (req, _res) => {
      // Checks if IP or user-agent should be ignored by the rate limit
      if (matchesUserAgentSkipPrefix(req.headers['user-agent'], userAgentSkipPrefixes)) return true;
      if (!req.ip) return false;
      return isIpInSkipList(req.ip);
    },
  };
  return rateLimitOptions as Options;
};

// A 4xx raised while reading the request, by a middleware is a caller mistake, not a platform failure.
export const isClientRequestError = (error: any): boolean => {
  const status = error?.status ?? error?.statusCode;
  return typeof status === 'number' && status >= 400 && status < 500;
};

// The graphql-upload messages that are pure constants, so they can be safely relayed to the caller as they are.
const MULTIPART_SPEC_URL = 'https://github.com/jaydenseric/graphql-multipart-request-spec';
const SAFE_MULTIPART_MESSAGES = new Set([
  `Missing multipart field ‘operations’ (${MULTIPART_SPEC_URL}).`,
  `Missing multipart field ‘map’ (${MULTIPART_SPEC_URL}).`,
  `Misordered multipart fields; ‘map’ should follow ‘operations’ (${MULTIPART_SPEC_URL}).`,
  `Misordered multipart fields; files should follow ‘map’ (${MULTIPART_SPEC_URL}).`,
  `Invalid JSON in the ‘operations’ multipart field (${MULTIPART_SPEC_URL}).`,
  `Invalid JSON in the ‘map’ multipart field (${MULTIPART_SPEC_URL}).`,
  `Invalid type for the ‘operations’ multipart field (${MULTIPART_SPEC_URL}).`,
  `Invalid type for the ‘map’ multipart field (${MULTIPART_SPEC_URL}).`,
  'Request disconnected during file upload stream parsing.',
]);

// Built for everything else, from the parser error type then the status.
// The precise cause always stays in the log.
const CLIENT_ERROR_MESSAGES: Record<string, string> = {
  'entity.parse.failed': 'Invalid json in request body',
  'entity.too.large': 'Request body too large',
  'charset.unsupported': 'Unsupported charset',
  'encoding.unsupported': 'Unsupported content encoding',
  'request.aborted': 'Request aborted before completion',
  'request.size.invalid': 'Request size did not match the content length',
};

const CLIENT_STATUS_MESSAGES: Record<number, string> = {
  400: 'Bad request',
  413: 'Payload too large',
  415: 'Unsupported media type',
  499: 'Client closed request',
};

export const clientErrorResponse = (error: any) => {
  const status = error?.status ?? error?.statusCode ?? 400;
  const message = SAFE_MULTIPART_MESSAGES.has(error?.message)
    ? error.message
    : CLIENT_ERROR_MESSAGES[error?.type] ?? CLIENT_STATUS_MESSAGES[status] ?? 'Bad request';
  return { status, body: { status: 'error', error: message } };
};

// graphql-upload relays raw busboy parsing errors untouched, and those carry no status at all:
// 'Multipart: Boundary not found' when the content-type has no boundary, 'Malformed part header',
// 'Unexpected end of form' on a truncated stream. They are caller mistakes like the rest, so they
// are normalized to 400 instead of reaching the generic handler as a platform failure. Programmer
// error types are left alone, so a bug inside the parser still surfaces as a 500.
const PLATFORM_ERROR_NAMES = ['TypeError', 'RangeError', 'ReferenceError', 'EvalError'];

export const normalizeUploadError = (error: any) => {
  const hasStatus = typeof (error?.status ?? error?.statusCode) === 'number';
  if (isEmptyField(error) || hasStatus || PLATFORM_ERROR_NAMES.includes(error?.name)) {
    return error;
  }
  return Object.assign(error, { status: 400, statusCode: 400 });
};

// The platform accepts credentials in the query string (health_access_key, the OIDC code and
// state), and both originalUrl and referer carry it, so only the pathname is ever logged.
const withoutQueryString = (url: string | undefined): string | undefined => url?.split('?')[0];

// The schemes the platform authenticates with. An allowlist, not the first word of the header: a
// malformed client can send a raw credential with no separating space, and splitting would then log
// the whole token as the scheme. Anything unrecognised is reported as 'unknown'.
const KNOWN_AUTH_SCHEMES = ['Bearer', 'Basic'];

// The scheme only (Bearer...etc), never the token. 'session' and 'unauthenticated' are spelled out rather than
// left absent, so a missing authScheme always means a bug here and not an anonymous caller.
const requestAuthScheme = (req: Request): string => {
  const authorization = req.headers.authorization;
  if (isEmptyField(authorization)) {
    return req.session?.user ? 'session' : 'unauthenticated';
  }
  const [scheme] = (authorization as string).split(' ');
  return KNOWN_AUTH_SCHEMES.find((known) => known.toLowerCase() === scheme.toLowerCase()) ?? 'unknown';
};

// Add as much non sensitive data as possible for malformatted requests.
export const logMalformedRequest = (req: Request, error: any, message = 'Malformed http request call'): void => {
  logApp.info(message, {
    reason: error?.message,
    errorName: error?.name,
    errorType: error?.type, // body-parser: entity.parse.failed, entity.too.large, ...
    status: error?.status ?? error?.statusCode,
    method: req.method,
    path: withoutQueryString(req.originalUrl ?? req.url),
    userId: req.session?.user?.id,
    authScheme: requestAuthScheme(req),
    userAgent: req.headers['user-agent'] ?? 'unknown',
    ip: req.ip ?? 'unknown',
    forwardedFor: req.headers['x-forwarded-for'], // req.ip is the proxy unless it is a trusted one
    referer: withoutQueryString(req.headers?.referer),
    contentType: req.headers['content-type'],
    contentLength: req.headers['content-length'],
    workId: req.headers['opencti-work-id'],
    draftId: req.headers['opencti-draft-id'],
  });
};

/**
 * Align the server keep-alive with the idle timeout of the front load balancer / reverse proxy.
 * The Node.js default of 5s is shorter than the idle timeout of a standard proxy (60s for an AWS
 * ALB), so the platform closes idle sockets the proxy still considers usable and the clients get
 * intermittent 502. headersTimeout is left to the Node.js default: it only bounds the reception of
 * the headers of a request already started and never counts keep-alive idle time, so it does not
 * have to be kept above keepAliveTimeout.
 */
export const applyKeepAliveTimeout = (server: Server) => {
  const keepAliveTimeout = getKeepAliveTimeout();
  server.keepAliveTimeout = keepAliveTimeout;
  return keepAliveTimeout;
};
