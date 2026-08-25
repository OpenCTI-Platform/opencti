import { describe, it, expect } from 'vitest';
import { parseConnectorLogsError, connectorErrorSummary } from './connectorErrors';

const jsonLog = (level: string, message: string, timestamp = '2026-01-01T00:00:00.000Z') => JSON.stringify({ timestamp, level, name: 'connector', message });

describe('parseConnectorLogsError', () => {
  it('returns no error for empty or nullish logs', () => {
    expect(parseConnectorLogsError(null).inError).toBe(false);
    expect(parseConnectorLogsError(undefined).inError).toBe(false);
    expect(parseConnectorLogsError([]).inError).toBe(false);
    expect(parseConnectorLogsError([null, '']).inError).toBe(false);
  });

  it('detects a 401 error from a JSON error log line', () => {
    const state = parseConnectorLogsError([
      jsonLog('INFO', 'Starting connector'),
      jsonLog('ERROR', 'API request failed with status_code=401 Unauthorized'),
    ]);
    expect(state.inError).toBe(true);
    expect(state.code).toBe(401);
  });

  it('detects a 403 error and prefers 403 when both codes appear', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', 'Received 403 Forbidden after 401 retry'),
    ]);
    expect(state.inError).toBe(true);
    expect(state.code).toBe(403);
  });

  it('detects errors from plain-text (non-JSON) log lines', () => {
    const state = parseConnectorLogsError([
      'Traceback: requests.exceptions.HTTPError: 401 Client Error: Unauthorized',
    ]);
    expect(state.inError).toBe(true);
    expect(state.code).toBe(401);
  });

  it('ignores a 401 mentioned on a non-error info line', () => {
    const state = parseConnectorLogsError([
      jsonLog('INFO', 'Connector will handle 401 responses gracefully'),
    ]);
    expect(state.inError).toBe(false);
  });

  it('clears the error when a later success line is logged', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', 'Authentication failed: 401 Unauthorized'),
      jsonLog('INFO', 'Successfully connected to the remote API'),
    ]);
    expect(state.inError).toBe(false);
  });

  it('keeps the error when only configuration errors are logged (no success)', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', 'Invalid credentials (401)'),
      jsonLog('ERROR', 'Invalid credentials (401)'),
      jsonLog('ERROR', 'Invalid credentials (401)'),
    ]);
    expect(state.inError).toBe(true);
    expect(state.code).toBe(401);
  });

  it('re-enters error state if a new error follows a recovery', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', '401 Unauthorized'),
      jsonLog('INFO', 'connection established'),
      jsonLog('ERROR', '403 Forbidden'),
    ]);
    expect(state.inError).toBe(true);
    expect(state.code).toBe(403);
  });

  it('does not clear an error from a success keyword on an error line', () => {
    const state = parseConnectorLogsError([
      jsonLog('ERROR', '401 Unauthorized'),
      jsonLog('ERROR', 'Retry did not succeed, still 200 attempts remaining'),
    ]);
    expect(state.inError).toBe(true);
  });
});

describe('connectorErrorSummary', () => {
  it('returns null when there is no error', () => {
    expect(connectorErrorSummary({ inError: false, code: null, message: null, timestamp: null })).toBeNull();
  });

  it('builds a readable summary for a 401', () => {
    const summary = connectorErrorSummary({ inError: true, code: 401, message: 'Invalid credentials', timestamp: null });
    expect(summary).toContain('401');
    expect(summary).toContain('Invalid credentials');
  });
});
