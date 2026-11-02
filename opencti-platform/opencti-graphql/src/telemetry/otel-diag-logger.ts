import { type DiagLogger, DiagLogLevel, diag } from '@opentelemetry/api';

// Minimal shape of the platform logger (logApp in config/conf) this adapter writes to.
export interface OtelDiagTarget {
  error: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  info: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

const OTEL_LOG_PREFIX = '[OPENCTI] [TELEMETRY]';

const toMeta = (args: unknown[]): Record<string, unknown> => {
  if (args.length === 0) {
    return {};
  }
  const details = args.map((arg) => (arg instanceof Error ? { name: arg.name, message: arg.message, stack: arg.stack } : arg));
  return { otel_details: details };
};

// OpenTelemetry reports exporter failures (connection refused, DNS failure, wrong path, 401/403)
// through its diag API only. Without a registered DiagLogger they are dropped, so an operator never
// sees why no trace or metric reaches the collector. This adapter forwards them to the platform logs.
export const createOtelDiagLogger = (target: OtelDiagTarget): DiagLogger => ({
  error: (message: string, ...args: unknown[]) => target.error(`${OTEL_LOG_PREFIX} ${message}`, toMeta(args)),
  warn: (message: string, ...args: unknown[]) => target.warn(`${OTEL_LOG_PREFIX} ${message}`, toMeta(args)),
  info: (message: string, ...args: unknown[]) => target.info(`${OTEL_LOG_PREFIX} ${message}`, toMeta(args)),
  debug: (message: string, ...args: unknown[]) => target.debug(`${OTEL_LOG_PREFIX} ${message}`, toMeta(args)),
  verbose: (message: string, ...args: unknown[]) => target.debug(`${OTEL_LOG_PREFIX} ${message}`, toMeta(args)),
});

// Registers the adapter as the global OpenTelemetry diag logger. WARN keeps export failures
// (reported at error level by the OTLP exporters) and drops the SDK's chatty info and debug lines.
export const registerOtelDiagLogger = (target: OtelDiagTarget, logLevel: DiagLogLevel = DiagLogLevel.WARN): boolean => {
  return diag.setLogger(createOtelDiagLogger(target), { logLevel, suppressOverrideMessage: true });
};
