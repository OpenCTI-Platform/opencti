// Compact authentication error status of a connector, mirroring the backend
// `ConnectorErrorStatus` GraphQL type. The detection (HTTP 401 / 403) is now
// performed server-side when the XTM Composer pushes logs, so the frontend only
// consumes this small object instead of fetching and parsing the whole logs
// array on every poll.

export type ConnectorErrorCode = 401 | 403 | 404;

export interface ConnectorErrorState {
  inError: boolean;
  code: ConnectorErrorCode | null;
  message: string | null;
  timestamp: string | null;
}

export const NO_CONNECTOR_ERROR: ConnectorErrorState = { inError: false, code: null, message: null, timestamp: null };

interface RawConnectorError {
  readonly in_error: boolean;
  readonly code?: number | null;
  readonly message?: string | null;
  readonly timestamp?: string | null;
}

/**
 * Maps the backend `manager_connector_error` field to the frontend error state.
 */
export const toConnectorErrorState = (raw: RawConnectorError | null | undefined): ConnectorErrorState => {
  if (!raw || !raw.in_error) return NO_CONNECTOR_ERROR;
  const code = raw.code === 401 || raw.code === 403 || raw.code === 404 ? raw.code : null;
  return {
    inError: true,
    code,
    message: raw.message ?? null,
    timestamp: raw.timestamp ?? null,
  };
};

/**
 * Short, tooltip-friendly summary of an error state. Returns null when there is
 * no error.
 */
export const connectorErrorSummary = (state: ConnectorErrorState): string | null => {
  if (!state.inError) return null;
  if (state.code === null) return state.message ?? null;
  let reason: string;
  if (state.code === 401) reason = 'Unauthorized (401)';
  else if (state.code === 403) reason = 'Forbidden (403)';
  else reason = 'Not found (404)';
  return state.message ? `${reason}: ${state.message}` : reason;
};
