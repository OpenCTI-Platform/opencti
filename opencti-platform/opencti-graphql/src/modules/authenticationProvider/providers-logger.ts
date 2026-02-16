// For now, it's only a logApp, but will be also send to UI via Redis.
import type { EnvStrategyType } from './providers-configuration';
import type { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';

export const logAuthInfo = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType, meta?: any) => {
  logApp.info(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthError = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType | undefined, meta?: any) => {
  logApp.error(`[Auth][${strategyType ? strategyType.toUpperCase() : 'Not provided'}]${message}`, { meta });
};

export interface AuthenticationProviderLogger {
  info: (message: string, meta?: any) => void;
  warn: (message: string, meta?: any) => void;
  error: (message: string, meta?: any) => void;
}

export const createAuthLogger = (type: AuthenticationProviderType, identifier: string): AuthenticationProviderLogger => {
  const logPrefix = `[Auth-${type.toUpperCase()}] `;
  return ({
    info: (message: string, meta: any = {}) => logApp.info(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } }),
    warn: (message: string, meta: any = {}) => logApp.warn(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } }),
    error: (message: string, meta: any = {}) => logApp.error(`${logPrefix}${message}`, { meta: { ...meta, type, identifier } }),
  });
};
