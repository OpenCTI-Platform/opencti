import type Express from 'express';
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
