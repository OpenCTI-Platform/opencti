import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import bytes from 'bytes';
import { booleanConf, logApp } from '../config/conf';
import { isEmptyField } from '../database/utils';
import { URL } from 'node:url';
import { type Options } from 'express-rate-limit';
import { getRateProtectionIpSkipList, getRateProtectionMaxRequests, getRateProtectionTimeWindowMs } from './httpConfig';

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

// graphql-upload accepts files of any size and in any number by default, so a single request could fill the
// temporary directory where uploads are buffered, then the platform storage.
// Artifacts (malware samples) can legitimately weigh up to 1GB, each platform can tighten these limits.
export const DEFAULT_MAX_UPLOAD_FILE_SIZE = '1gb';
export const DEFAULT_MAX_UPLOAD_FILES = 20;

interface GraphqlUploadOptions {
  maxFileSize: number;
  maxFiles: number;
}

const parsePositiveSize = (size: string | number): number | null => {
  const parsed = bytes.parse(size);
  return parsed !== null && Number.isFinite(parsed) && parsed > 0 ? parsed : null;
};

const parsePositiveInteger = (value: string | number): number | null => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
};

// An unparsable file limit falls back to the platform default, never to graphql-upload unlimited default.
export const buildGraphqlUploadOptions = (
  uploadFileSizeLimit: string | number = DEFAULT_MAX_UPLOAD_FILE_SIZE,
  uploadMaxFiles: string | number = DEFAULT_MAX_UPLOAD_FILES,
): GraphqlUploadOptions => {
  const maxFileSize = parsePositiveSize(uploadFileSizeLimit) ?? bytes.parse(DEFAULT_MAX_UPLOAD_FILE_SIZE) as number;
  const maxFiles = parsePositiveInteger(uploadMaxFiles) ?? DEFAULT_MAX_UPLOAD_FILES;
  return { maxFileSize, maxFiles };
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
