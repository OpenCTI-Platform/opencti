// For now, it's only a logApp, but will be also send to UI via Redis.
import type { EnvStrategyType } from './providers-configuration';
import type { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { redisPushAuthLog } from '../../database/redis';
import { forgetPromise } from '../../utils/promiseUtils';
import type { CERT_PROVIDER_NAME } from './provider-cert';
import type { HEADERS_PROVIDER_NAME } from './provider-headers';

export const logAuthInfo = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType, meta?: any) => {
  logApp.info(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthError = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType | undefined, meta?: any) => {
  logApp.error(`[Auth][${strategyType ? strategyType.toUpperCase() : 'Not provided'}]${message}`, { meta });
};

export interface AuthenticationProviderLogger {
  success: (message: string, meta?: any) => void;
  info: (message: string, meta?: any) => void;
  warn: (message: string, meta?: any) => void;
  error: (message: string, meta?: any, err?: any) => void;
  deferError: (message: string, meta?: any, err?: any) => () => void;
}

export class AuthenticationProviderError extends Error {
  public readonly meta: any;
  constructor(message: string, meta?: any) {
    super(message);
    this.name = 'AuthenticationProviderError';
    this.meta = meta;
  }
}

export const createAuthLogger = (
  id: string,
  type: AuthenticationProviderType | typeof HEADERS_PROVIDER_NAME | typeof CERT_PROVIDER_NAME,
  identifier: string,
): AuthenticationProviderLogger => {
  const logPrefix = `[Auth-${type.toUpperCase()}] `;
  const doLogError = (message: string, meta: any, err?: any) => {
    const isAuthError = err instanceof AuthenticationProviderError;
    const messageText = isAuthError ? err.message : message;
    const realMeta = {
      ...(isAuthError ? err.meta : meta),
      ...(err && !isAuthError ? { message: err.message } : {}),
    };
    forgetPromise(redisPushAuthLog(id, { level: 'error', type, identifier, message: messageText, meta: realMeta }));
  };
  return ({
    success: (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog(id, { level: 'success', type, identifier, message, meta }));
    },
    info: (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog(id, { level: 'info', type, identifier, message, meta }));
    },
    warn: (message, meta = {}) => {
      logApp.warn(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog(id, { level: 'warn', type, identifier, message, meta }));
    },
    error: (message, meta = {}, err?) => {
      logApp.error(`${logPrefix}${message}`, { err, meta: { ...meta, type, identifier } });
      doLogError(message, meta, err);
    },
    deferError: (message, meta = {}, err?) => {
      logApp.error(`${logPrefix}${message}`, { err, meta: { ...meta, type, identifier } });
      return () => doLogError(message, meta, err);
    },
  });
};
