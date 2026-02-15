// For now, it's only a logApp, but will be also send to UI via Redis.
import type { EnvStrategyType } from './providers-configuration';
import type { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';

export const logAuthInfo = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType, meta?: any) => {
  logApp.info(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthWarn = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType, meta?: any) => {
  logApp.warn(`[Auth][${strategyType.toUpperCase()}]${message}`, { meta });
};

export const logAuthError = (message: string, strategyType: EnvStrategyType | AuthenticationProviderType | undefined, meta?: any) => {
  logApp.error(`[Auth][${strategyType ? strategyType.toUpperCase() : 'Not provided'}]${message}`, { meta });
};
