import { logs, SeverityNumber } from '@opentelemetry/api-logs';
import type { AnyValueMap } from '@opentelemetry/api-logs';
import { type AppModule, classifyFrontendError, resolveRouteModule } from './errorOrigin';

export const LOGGER_NAME = 'opencti-front';

export const SEVERITY_NUMBERS = {
  DEBUG: SeverityNumber.DEBUG,
  INFO: SeverityNumber.INFO,
  WARN: SeverityNumber.WARN,
  ERROR: SeverityNumber.ERROR,
};

export type LogLevel = keyof typeof SEVERITY_NUMBERS;

export interface LogOptions {
  eventName: string;
  data?: Record<string, unknown>;
  error?: unknown;
  // The module whose code raised the error, e.g. given by a module error boundary (RFC 0006).
  // Without it, the record goes to the module of the page the user is on.
  module?: AppModule;
}

// RFC 0006 fields: `entry_module` and `module` for every record, `origin` and `dependency` for a record
// carrying an error. The backend derives the level of a classified record from its origin.
const scopeAttributes = (options: LogOptions) => {
  const entryModule = typeof window !== 'undefined' ? resolveRouteModule(window.location.pathname) : undefined;
  const module = options.module ?? entryModule;
  const classification = options.error !== undefined ? classifyFrontendError(options.error) : undefined;
  return {
    ...(module ? { module } : {}),
    ...(entryModule ? { entry_module: entryModule } : {}),
    ...(classification ? { origin: classification.origin } : {}),
    ...(classification?.dependency ? { dependency: classification.dependency } : {}),
  };
};

const emit = (level: LogLevel, message: string, options: LogOptions) => {
  try {
    logs.getLogger(LOGGER_NAME).emit({
      eventName: options.eventName,
      severityText: level,
      severityNumber: SEVERITY_NUMBERS[level],
      body: message,
      attributes: {
        ...(options.data ? { data: options.data as AnyValueMap } : {}),
        ...scopeAttributes(options),
      },
      exception: options.error,
    });
  } catch {
    // A logging failure must never surface
  }
};

// `message` is a constant string, everything variable goes into `data`, so that
// records of the same event group together instead of each being unique.
export const logger = {
  debug: (message: string, options: LogOptions) => emit('DEBUG', message, options),
  info: (message: string, options: LogOptions) => emit('INFO', message, options),
  warn: (message: string, options: LogOptions) => emit('WARN', message, options),
  error: (message: string, options: LogOptions) => emit('ERROR', message, options),
};
