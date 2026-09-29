import { logs, SeverityNumber } from '@opentelemetry/api-logs';
import type { AnyValueMap } from '@opentelemetry/api-logs';

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
}

const emit = (level: LogLevel, message: string, options: LogOptions) => {
  try {
    logs.getLogger(LOGGER_NAME).emit({
      eventName: options.eventName,
      severityText: level,
      severityNumber: SEVERITY_NUMBERS[level],
      body: message,
      attributes: options.data ? { data: options.data as AnyValueMap } : {},
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
