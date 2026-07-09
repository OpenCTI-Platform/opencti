import { AxiosError } from 'axios';
import { redisPushIngestionLog } from '../../database/redis';
import { logApp } from '../../config/conf';

export interface IngestionLogger {
  info: (message: string, meta?: Record<string, unknown>) => void;
  success: (message: string, meta?: Record<string, unknown>) => Promise<void>;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => Promise<void>;
}

export const createIngestionLogger = (feedId: string, feedName: string, feedType: string): IngestionLogger => {
  const logPrefix = `[Ingestion-${feedType.toUpperCase()}] `;
  return {
    info: (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, feedName } });
      redisPushIngestionLog(feedId, { level: 'info', type: feedType, identifier: feedName, message, meta }).catch((err) => {
        logApp.error(`${logPrefix}Failed to push info log to Redis`, { cause: err });
      });
    },
    success: async (message, meta = {}) => {
      logApp.info(`${logPrefix}${message}`, { meta: { ...meta, feedName } });
      await redisPushIngestionLog(feedId, { level: 'success', type: feedType, identifier: feedName, message, meta });
    },
    warn: (message, meta = {}) => {
      logApp.warn(`${logPrefix}${message}`, { meta: { ...meta, feedName } });
      redisPushIngestionLog(feedId, { level: 'warn', type: feedType, identifier: feedName, message, meta }).catch((err) => {
        logApp.error(`${logPrefix}Failed to push warn log to Redis`, { cause: err });
      });
    },
    error: async (message, meta = {}) => {
      logApp.error(`${logPrefix}${message}`, { meta: { ...meta, feedName } });
      await redisPushIngestionLog(feedId, { level: 'error', type: feedType, identifier: feedName, message, meta });
    },
  };
};

export const buildIngestionErrorMeta = (e: Error): Record<string, unknown> => {
  if (e instanceof AxiosError) {
    return {
      error_code: e.code,
      ...(e.response ? {
        http_status: e.response.status,
        http_status_text: e.response.statusText,
        ...(e.response.headers['cf-mitigated'] ? { cloudflare: 'Cloudflare challenge fail' } : {}),
      } : {}),
    };
  }
  return { error: e.message };
};
