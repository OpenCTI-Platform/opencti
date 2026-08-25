import { describe, it, expect } from 'vitest';
import { parseConnectorLogsError } from '../../../src/domain/connectorErrors';

const jsonLog = (level: string, message: string, timestamp = '2026-01-01T00:00:00.000Z') => JSON.stringify({ timestamp, level, name: 'connector', message });

describe('parseConnectorLogsError', () => {
  it('returns no error for empty or nullish logs', () => {
    expect(parseConnectorLogsError(null).in_error).toBe(false);
    expect(parseConnectorLogsError(undefined).in_error).toBe(false);
    expect(parseConnectorLogsError([]).in_error).toBe(false);
    expect(parseConnectorLogsError([null, '']).in_error).toBe(false);
  });

  it('detects a 401 error from a JSON error log line', () => {
    const state = parseConnectorLogsError([
      jsonLog('INFO', 'Starting connector'),
      jsonLog('ERROR', 'API request failed with status_code=401 Unauthorized'),
    ]);
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(401);
  });

  it('detects a 403 error and prefers 403 when both codes appear', () => {
    const state = parseConnectorLogsError([jsonLog('ERROR', 'Received 403 Forbidden after 401 retry')]);
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(403);
  });

  it('detects errors from plain-text (non-JSON) log lines', () => {
    const state = parseConnectorLogsError(['Traceback: requests.exceptions.HTTPError: 401 Client Error: Unauthorized']);
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(401);
  });

  it('ignores a 401 mentioned on a non-error info line', () => {
    const state = parseConnectorLogsError([jsonLog('INFO', 'Connector will handle 401 responses gracefully')]);
    expect(state.in_error).toBe(false);
  });

  it('clears the error when a later success line is logged', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', 'Authentication failed: 401 Unauthorized'),
      jsonLog('INFO', 'Successfully connected to the remote API'),
    ]);
    expect(state.in_error).toBe(false);
  });

  it('keeps the error when only configuration errors are logged (no success)', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', 'Invalid credentials (401)'),
      jsonLog('ERROR', 'Invalid credentials (401)'),
      jsonLog('ERROR', 'Invalid credentials (401)'),
    ]);
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(401);
  });

  it('re-enters error state if a new error follows a recovery', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', '401 Unauthorized'),
      jsonLog('INFO', 'connection established'),
      jsonLog('ERROR', '403 Forbidden'),
    ]);
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(403);
  });

  it('does not clear an error from a success keyword on an error line', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', '401 Unauthorized'),
      jsonLog('ERROR', 'Retry did not succeed, still 200 attempts remaining'),
    ]);
    expect(state.in_error).toBe(true);
  });

  it('ignores error lines older than the reset watermark', () => {
    const state = parseConnectorLogsError(
      [jsonLog('ERROR', '401 Unauthorized', '2026-01-01T00:00:00.000Z')],
      '2026-01-01T01:00:00.000Z',
    );
    expect(state.in_error).toBe(false);
  });

  it('flags an error logged after the reset watermark', () => {
    const state = parseConnectorLogsError(
      [
        jsonLog('ERROR', '401 Unauthorized', '2026-01-01T00:00:00.000Z'),
        jsonLog('ERROR', '403 Forbidden', '2026-01-01T02:00:00.000Z'),
      ],
      '2026-01-01T01:00:00.000Z',
    );
    expect(state.in_error).toBe(true);
    expect(state.code).toBe(403);
  });
});
