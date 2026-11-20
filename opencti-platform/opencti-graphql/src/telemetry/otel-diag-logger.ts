import { type DiagLogger, DiagLogLevel, diag } from '@opentelemetry/api';

// Minimal shape of the platform logger (logApp in config/conf) this adapter writes to.
export interface OtelDiagTarget {
  error: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  info: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

export interface OtelDiagLoggerOptions {
  // Minimum delay between two records of the same failure message.
  throttleMs?: number;
  now?: () => number;
}

const OTEL_LOG_PREFIX = '[OPENCTI] [TELEMETRY]';
const DEFAULT_THROTTLE_MS = 5 * 60 * 1000;
const MAX_THROTTLE_KEYS = 100;
const TIMEOUT_HINT = 'an export timeout usually means the collector is unreachable: check the exporter URL and port';

interface NormalizedRecord {
  message: string;
  meta: Record<string, unknown>;
}

const toMeta = (args: unknown[]): Record<string, unknown> => {
  if (args.length === 0) {
    return {};
  }
  const details = args.map((arg) => (arg instanceof Error ? { name: arg.name, message: arg.message, stack: arg.stack } : arg));
  return { otel_details: details };
};

// The SDK readers and span processors report export failures through globalErrorHandler, which calls
// diag.error(JSON.stringify(exception)): one JSON string holding the whole serialized exception.
// Keep its message as the log message (stable, so it can be grouped and alerted on) and its stack as metadata.
const messageToString = (message: unknown): string => {
  if (typeof message === 'string') {
    return message;
  }
  if (message instanceof Error) {
    return message.message || message.name || 'Error';
  }
  if (message === null || message === undefined) {
    return String(message);
  }
  try {
    return typeof message === 'object' ? JSON.stringify(message) : String(message);
  } catch {
    return String(message);
  }
};

const parseSerializedException = (message: string): { message: string; name?: string; stack?: string } | null => {
  const trimmed = message.trim();
  if (!trimmed.startsWith('{')) {
    return null;
  }
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed === null || typeof parsed !== 'object') {
      return null;
    }
    const stack = typeof parsed.stack === 'string' ? parsed.stack : undefined;
    const parsedMessage = typeof parsed.message === 'string' && parsed.message.length > 0
      ? parsed.message
      : stack?.split('\n')[0];
    if (!parsedMessage) {
      return null;
    }
    return { message: parsedMessage, name: typeof parsed.name === 'string' ? parsed.name : undefined, stack };
  } catch {
    return null;
  }
};

const normalize = (rawMessage: unknown, args: unknown[]): NormalizedRecord => {
  const meta = toMeta(rawMessage instanceof Error ? [rawMessage, ...args] : args);
  const message = messageToString(rawMessage);
  const exception = parseSerializedException(message);
  const text = exception ? exception.message : message;
  if (exception) {
    meta.otel_error = { name: exception.name, stack: exception.stack };
  }
  const hint = /timed out/i.test(text) ? ` (${TIMEOUT_HINT})` : '';
  return { message: `${OTEL_LOG_PREFIX} ${text}${hint}`, meta };
};

// OpenTelemetry reports exporter failures (connection refused, DNS failure, wrong path, 401/403)
// through its diag API only. Without a registered DiagLogger they are dropped, so an operator never
// sees why no trace or metric reaches the collector. This adapter forwards them to the platform logs.
// A failing collector is an external dependency: its failures are logged at warn, never error, and
// each distinct failure is logged once, then at most once per throttle window with the count of
// the records suppressed in between, so a collector that stays down cannot flood the logs.
export const createOtelDiagLogger = (target: OtelDiagTarget, options: OtelDiagLoggerOptions = {}): DiagLogger => {
  const throttleMs = options.throttleMs ?? DEFAULT_THROTTLE_MS;
  const now = options.now ?? Date.now;
  const seen = new Map<string, { at: number; suppressed: number }>();
  const throttledWarn = (rawMessage: unknown, args: unknown[]) => {
    const { message, meta } = normalize(rawMessage, args);
    const time = now();
    const entry = seen.get(message);
    if (entry && time - entry.at < throttleMs) {
      entry.suppressed += 1;
      return;
    }
    const suppressed = entry?.suppressed ?? 0;
    target.warn(message, suppressed > 0 ? { ...meta, otel_suppressed_count: suppressed } : meta);
    if (!entry && seen.size >= MAX_THROTTLE_KEYS) {
      const oldest = seen.keys().next().value;
      if (oldest !== undefined) {
        seen.delete(oldest);
      }
    }
    seen.set(message, { at: time, suppressed: 0 });
  };
  // A diagnostics logger must never break the process it observes: any failure here is swallowed.
  const safe = (fn: () => void) => {
    try {
      fn();
    } catch {
      // ignore
    }
  };
  return {
    error: (message: unknown, ...args: unknown[]) => safe(() => throttledWarn(message, args)),
    warn: (message: unknown, ...args: unknown[]) => safe(() => throttledWarn(message, args)),
    info: (message: unknown, ...args: unknown[]) => safe(() => {
      const record = normalize(message, args);
      target.info(record.message, record.meta);
    }),
    debug: (message: unknown, ...args: unknown[]) => safe(() => {
      const record = normalize(message, args);
      target.debug(record.message, record.meta);
    }),
    verbose: (message: unknown, ...args: unknown[]) => safe(() => {
      const record = normalize(message, args);
      target.debug(record.message, record.meta);
    }),
  };
};

// Exporter URLs may carry credentials (user:password@) or tokens in the query string or fragment:
// keep only the scheme, host, port and path before writing one to the logs.
export const sanitizeExporterUrl = (url: unknown): string => {
  if (typeof url !== 'string' || url.trim().length === 0) {
    return '';
  }
  try {
    const parsed = new URL(url.trim());
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return '[unparseable URL]';
  }
};

// Registers the adapter as the global OpenTelemetry diag logger. WARN keeps export failures
// (reported at error level by the SDK) and drops the SDK's chatty info and debug lines.
export const registerOtelDiagLogger = (
  target: OtelDiagTarget,
  logLevel: DiagLogLevel = DiagLogLevel.WARN,
  options: OtelDiagLoggerOptions = {},
): boolean => {
  return diag.setLogger(createOtelDiagLogger(target, options), { logLevel, suppressOverrideMessage: true });
};
