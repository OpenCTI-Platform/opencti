// For now, it's only a logApp, but will be also send to UI via Redis.
import type { EnvStrategyType } from './providers-configuration';
import type { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { redisPushAuthLog } from '../../database/redis';
import { CERT_PROVIDER_NAME, HEADERS_PROVIDER_NAME } from './providers';
import { forgetPromise } from '../../utils/promiseUtils';

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
}

export class AuthenticationProviderError extends Error {
  public readonly meta: any;
  constructor(message: string, meta?: any) {
    super(message);
    this.name = 'AuthenticationProviderError';
    this.meta = meta;
  }
}

export const createAuthLogger = (type: AuthenticationProviderType | typeof HEADERS_PROVIDER_NAME | typeof CERT_PROVIDER_NAME, identifier: string): AuthenticationProviderLogger => {
  const logPrefix = `[Auth-${type.toUpperCase()}] `;
  return ({
    success: (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog({ level: 'success', type, identifier, message, meta }));
    },
    info: (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog({ level: 'info', type, identifier, message, meta }));
    },
    warn: (message, meta = {}) => {
      logApp.warn(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } });
      forgetPromise(redisPushAuthLog({ level: 'warn', type, identifier, message, meta }));
    },
    error: (message, meta = {}, err?) => {
      const isAuthError = err instanceof AuthenticationProviderError;
      const messageText = isAuthError ? err.message : message;
      const realMeta = {
        ...(isAuthError ? err.meta : meta),
        ...(err && !isAuthError ? { message: err.message } : {}),
      };
      logApp.error(`${logPrefix}${messageText}`, { err: isAuthError ? undefined : err, meta: { ...realMeta, type, identifier } });
      forgetPromise(redisPushAuthLog({ level: 'error', type, identifier, message: messageText, meta: realMeta }));
    },
  });
};
