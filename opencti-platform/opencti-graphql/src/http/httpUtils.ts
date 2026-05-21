import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { booleanConf, logApp } from '../config/conf';
import { isEmptyField } from '../database/utils';
import { URL } from 'node:url';
import {
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

export const setCookieError = (res: Response, message: string) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
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

export const buildPublicHelmetParameters = () => {
  const ancestorsFromConfig = getPublicAuthorizedDomainsFromConfiguration();
  const frameAncestorDomains = ancestorsFromConfig === '' ? "'none'" : ancestorsFromConfig;
  const allowedFrameSrc = ["'self'"];
  const helmetConfiguration: HelmetOptions = {
    referrerPolicy: { policy: 'unsafe-url' },
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

export const buildDefaultHelmetParameters = () => {
  const helmetConfiguration: HelmetOptions = {
    referrerPolicy: { policy: 'unsafe-url' },
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
