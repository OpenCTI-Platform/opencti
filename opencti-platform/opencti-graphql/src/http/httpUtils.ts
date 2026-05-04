import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { booleanConf, logApp } from '../config/conf';
import { isEmptyField } from '../database/utils';
import { URL } from 'node:url';
import {
  getPublicAuthorizedDomainsFromConfiguration,
  getRateProtectionIpSkipList,
  getRateProtectionMaxRequests,
  getRateProtectionTimeWindowMs,
  isDevMode,
  isUnsecureHttpResourceAllowed,
} from './httpConfig';
import type { HelmetOptions } from 'helmet';
import { type Options } from 'express-rate-limit';

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
  const imgSrc = ["'self'", 'data:', 'https://*'];
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
        frameSrc: allowedFrameSrc,
        frameAncestors: frameAncestorDomains,
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
        frameAncestors: "'none'",
      },
    },
    xFrameOptions: { action: 'deny' },
  };
  return helmetConfiguration;
};

export const buildRateLimiterOptions = (): Options => {
  const skipList: string[] = getRateProtectionIpSkipList();
  const rateLimitOptions: Partial<Options> = {
    windowMs: getRateProtectionTimeWindowMs(),
    limit: getRateProtectionMaxRequests(),
    handler: (req, res /* , next */) => {
      logApp.debug(`[RATE-LIMIT] over quota for ${req?.ip}`);
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
    skip: (req, _res) => req.ip ? skipList.includes(req.ip) : false,
  };
  return rateLimitOptions as Options;
};
