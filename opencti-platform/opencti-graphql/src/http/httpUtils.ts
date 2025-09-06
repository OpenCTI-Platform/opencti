import type Express from 'express';
import { booleanConf } from '../config/conf';

export const setCookieError = (res: Express.Response, message: string) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
    maxAge: 10000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
    sameSite: 'strict',
  });
};
