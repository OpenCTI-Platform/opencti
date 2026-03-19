import type Express from 'express';
import crypto from 'node:crypto';
import { booleanConf, logApp } from '../config/conf';
import { isEmptyField } from '../database/utils';
import { URL } from 'node:url';

export const setCookieError = (res: Express.Response, message: string) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
    maxAge: 10000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
    sameSite: 'strict',
  });
};

export const extractRefererPathFromReq = (req: Express.Request) => {
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
export const encodeOidcState = (referer: string): string => {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = JSON.stringify({ n: nonce, r: referer });
  return Buffer.from(payload).toString('base64url');
};

/**
 * Decode a referer path from an OIDC state parameter.
 * Returns undefined if the state is not a valid encoded referer
 * (e.g. a random state from a different strategy or a corrupted value).
 */
export const decodeOidcState = (state: string | undefined): string | undefined => {
  if (!state) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
    const referer = payload?.r;
    if (typeof referer === 'string' && referer.length > 0) {
      return referer;
    }
    return undefined;
  } catch {
    return undefined;
  }
};
