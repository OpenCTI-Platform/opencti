import { logApp } from '../config/conf';

// Detects authentication errors (HTTP 401 / 403) in the raw runtime logs pushed
// by the XTM Composer via the `updateConnectorLogs` mutation. Parsing happens
// server-side the moment logs are received, so the resulting status is always
// fresh and the frontend only reads a compact object instead of the full logs.
//
// pycti connectors emit one JSON object per log line
// (`{"timestamp","level","message",...}`), but some connectors or the composer
// may emit plain text lines: the parser tolerates both.
//
// An auth error is only considered resolved when a later, non-error log line
// reports a successful operation. Configuration errors never emit a success
// line, so the error state is kept until an explicit recovery is observed.

export type ConnectorErrorCode = 401 | 403;

export interface ConnectorErrorStatus {
  in_error: boolean;
  code: ConnectorErrorCode | null;
  message: string | null;
  timestamp: string | null;
}

interface ParsedLogLine {
  level: string | null;
  message: string;
  timestamp: string | null;
}

export const NO_CONNECTOR_ERROR: ConnectorErrorStatus = { in_error: false, code: null, message: null, timestamp: null };

const ERROR_LEVELS = new Set(['error', 'critical', 'fatal', 'warning', 'warn']);

const AUTH_401_PATTERN = /\b401\b|\bunauthori[sz]ed\b|invalid credential|invalid or missing authentication|authentication failed|missing authentication|invalid api[-\s]?key|invalid token|expired token/i;
const AUTH_403_PATTERN = /\b403\b|\bforbidden\b|access denied|not authori[sz]ed|insufficient permission/i;
const SUCCESS_PATTERN = /\bsuccess(?:ful(?:ly)?)?\b|\bauthenticated\b|\bconnected\b|connection established|login successful|\b2\d\d\b|status_code=2\d\d|run\s+(?:complete|finished)|completed successfully/i;

const parseLogLine = (raw: string): ParsedLogLine => {
  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') {
        const level = typeof parsed.level === 'string' ? parsed.level.toLowerCase() : null;
        const message = typeof parsed.message === 'string' ? parsed.message : trimmed;
        const timestamp = typeof parsed.timestamp === 'string' ? parsed.timestamp : null;
        return { level, message, timestamp };
      }
    } catch {
      // Not valid JSON, fall through to plain-text handling.
    }
  }
  return { level: null, message: trimmed, timestamp: null };
};

const detectAuthCode = (text: string): ConnectorErrorCode | null => {
  // 403 (authenticated but not allowed) is the more specific case and wins when
  // both codes appear on the same line.
  if (AUTH_403_PATTERN.test(text)) return 403;
  if (AUTH_401_PATTERN.test(text)) return 401;
  return null;
};

const isErrorLevel = (level: string | null): boolean => {
  // Plain-text lines carry no level: they remain eligible to be errors so that
  // non-JSON connector output is not silently ignored.
  return level === null || ERROR_LEVELS.has(level);
};

/**
 * Scans a connector's raw logs (chronological, oldest first) and returns its
 * current authentication error status.
 *
 * @param logs the raw log lines pushed by the composer
 * @param since optional ISO timestamp watermark: log lines strictly older than
 *   this instant are ignored. Set when the connector is updated/started so that
 *   stale error lines predating the change never re-flag a connector that has
 *   just been reconfigured (a config error produces no success line to clear it).
 */
export const parseConnectorLogsError = (
  logs: ReadonlyArray<string | null> | null | undefined,
  since?: string | null,
): ConnectorErrorStatus => {
  if (!logs || logs.length === 0) return NO_CONNECTOR_ERROR;

  const sinceMs = since ? new Date(since).getTime() : Number.NaN;
  const hasWatermark = !Number.isNaN(sinceMs);

  let current: ConnectorErrorStatus = NO_CONNECTOR_ERROR;
  try {
    for (const raw of logs) {
      if (!raw) continue;
      const { level, message, timestamp } = parseLogLine(raw);

      // Skip log lines emitted before the last reset watermark: they belong to
      // a previous configuration and must not resurrect a cleared error.
      if (hasWatermark && timestamp) {
        const lineMs = new Date(timestamp).getTime();
        if (!Number.isNaN(lineMs) && lineMs < sinceMs) continue;
      }

      const code = detectAuthCode(message);
      if (code !== null && isErrorLevel(level)) {
        current = { in_error: true, code, message, timestamp };
        continue;
      }

      if (current.in_error && !ERROR_LEVELS.has(level ?? '') && SUCCESS_PATTERN.test(message)) {
        current = NO_CONNECTOR_ERROR;
      }
    }
  } catch (e) {
    logApp.warn('[CONNECTOR] Unable to parse connector logs for error detection', { cause: e });
    return NO_CONNECTOR_ERROR;
  }

  return current;
};
