// Utility to detect authentication errors (HTTP 401 / 403) in the raw runtime
// logs exposed by the `manager_connector_logs` GraphQL field on a connector.
//
// pycti connectors emit one JSON object per log line
// (`{"timestamp","level","name","message",...}`), but some connectors or the
// XTM Composer may emit plain text lines. The parser tolerates both.
//
// The core requirement is not only to spot a 401/403, but to know whether the
// connector is *still* in error: an auth error is considered resolved only when
// a later, non-error log line reports a successful operation. Configuration
// errors never produce a success line, so the error state is kept until an
// explicit recovery is observed.

export type ConnectorErrorCode = 401 | 403;

export interface ConnectorErrorState {
  inError: boolean;
  code: ConnectorErrorCode | null;
  message: string | null;
  timestamp: string | null;
}

interface ParsedLogLine {
  level: string | null;
  message: string;
  timestamp: string | null;
}

const ERROR_LEVELS = new Set(['error', 'critical', 'fatal', 'warning', 'warn']);

// A 401 anywhere in the line, or an explicit unauthorized/credentials wording.
const AUTH_401_PATTERN = /\b401\b|\bunauthori[sz]ed\b|invalid credential|invalid or missing authentication|authentication failed|missing authentication|invalid api[-\s]?key|invalid token|expired token/i;
// A 403 anywhere in the line, or an explicit forbidden/access-denied wording.
const AUTH_403_PATTERN = /\b403\b|\bforbidden\b|access denied|not authori[sz]ed|insufficient permission/i;

// Signals that the connector performed a successful operation again, which
// clears a previously observed auth error.
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
  // 403 is checked first: it is the more specific "authenticated but not
  // allowed" case and should win when both appear on the same line.
  if (AUTH_403_PATTERN.test(text)) return 403;
  if (AUTH_401_PATTERN.test(text)) return 401;
  return null;
};

const isErrorLevel = (level: string | null): boolean => {
  // Plain-text lines carry no level: they are still eligible to be errors so
  // that non-JSON connector output is not silently ignored.
  return level === null || ERROR_LEVELS.has(level);
};

/**
 * Scans a connector's raw logs (chronological, oldest first) and returns its
 * current authentication error state.
 */
export const parseConnectorLogsError = (
  logs: ReadonlyArray<string | null> | null | undefined,
): ConnectorErrorState => {
  const empty: ConnectorErrorState = { inError: false, code: null, message: null, timestamp: null };
  if (!logs || logs.length === 0) return empty;

  let current: ConnectorErrorState = empty;
  for (const raw of logs) {
    if (!raw) continue;
    const { level, message, timestamp } = parseLogLine(raw);

    const code = detectAuthCode(message);
    if (code !== null && isErrorLevel(level)) {
      current = { inError: true, code, message, timestamp };
      continue;
    }

    // A successful, non-error line after an auth error clears the error state.
    if (current.inError && !ERROR_LEVELS.has(level ?? '') && SUCCESS_PATTERN.test(message)) {
      current = empty;
    }
  }

  return current;
};

/**
 * Short, translatable-friendly summary of an error state, suitable for a
 * tooltip. Returns null when there is no error.
 */
export const connectorErrorSummary = (state: ConnectorErrorState): string | null => {
  if (!state.inError || state.code === null) return null;
  const reason = state.code === 401 ? 'Unauthorized (401)' : 'Forbidden (403)';
  return state.message ? `${reason}: ${state.message}` : reason;
};
