import type { FrontendLogInput } from '../generated/graphql';
import { type ErrorOrigin, levelForOrigin } from './error-origin';

const FRONTEND_LOG_LEVELS = {
  DEBUG: 'debug',
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error',
} as const;

// A record the UI classified (RFC 0006) takes its level from its origin, exactly as a backend record does
// (policy A): the level policy has a single implementation. A record without origin keeps the UI's level.
export const toFrontendLogEntry = (log: FrontendLogInput) => {
  const { timestamp, level, message, eventName, data, exception, module, entryModule, dependency } = log;
  const origin = log.origin as ErrorOrigin | null | undefined;
  return {
    level: origin ? levelForOrigin(origin) : (FRONTEND_LOG_LEVELS[level] ?? 'error'),
    message,
    meta: {
      client_timestamp: timestamp,
      event_name: eventName,
      data,
      exception,
      ...(origin ? { origin } : {}),
      ...(module ? { module } : {}),
      ...(entryModule ? { entry_module: entryModule } : {}),
      ...(origin === 'infra' && dependency ? { dependency } : {}),
    },
  };
};
