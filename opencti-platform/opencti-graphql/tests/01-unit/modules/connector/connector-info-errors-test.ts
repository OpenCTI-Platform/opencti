import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import {
  CONNECTOR_ERROR_CODE_MAX_LENGTH,
  CONNECTOR_ERROR_MESSAGE_MAX_LENGTH,
  CONNECTOR_ERRORS_MAX_COUNT,
  resolveConnectorInfo,
  sanitizeConnectorInfoErrors,
} from '../../../../src/modules/connector/connector-domain';
import type { BasicStoreEntityConnector, ConnectorInfoError } from '../../../../src/modules/connector/connector-types';

const API_ERROR: ConnectorInfoError = { code: 'API_UNREACHABLE', message: 'Source API returned 503', criticity: 2 };

describe('sanitizeConnectorInfoErrors', () => {
  it('should return an empty list for an empty list', () => {
    expect(sanitizeConnectorInfoErrors([])).toEqual([]);
  });

  it('should keep only code, message and criticity', () => {
    const withExtraField = { ...API_ERROR, stack: 'trace' } as ConnectorInfoError;
    expect(sanitizeConnectorInfoErrors([withExtraField])).toEqual([API_ERROR]);
  });

  it('should trim and truncate code and message', () => {
    const [error] = sanitizeConnectorInfoErrors([
      { code: `  ${'C'.repeat(300)}  `, message: `  ${'M'.repeat(2000)}  `, criticity: 0 },
    ]);
    expect(error.code).toBe('C'.repeat(CONNECTOR_ERROR_CODE_MAX_LENGTH));
    expect(error.message).toBe('M'.repeat(CONNECTOR_ERROR_MESSAGE_MAX_LENGTH));
  });

  it('should not split a character when truncating', () => {
    const [error] = sanitizeConnectorInfoErrors([{ code: 'EMOJI', message: '🔥'.repeat(2000), criticity: 0 }]);
    expect(error.message).toBe('🔥'.repeat(CONNECTOR_ERROR_MESSAGE_MAX_LENGTH));
  });

  it('should drop errors with a blank code', () => {
    expect(sanitizeConnectorInfoErrors([API_ERROR, { code: '   ', message: 'blank code', criticity: 3 }])).toEqual([API_ERROR]);
  });

  it('should sort errors from the most to the least critical', () => {
    const errors = [1, 3, 0, 2].map((criticity) => ({ code: `CRITICITY_${criticity}`, message: '', criticity }));
    expect(sanitizeConnectorInfoErrors(errors).map(({ criticity }) => criticity)).toEqual([3, 2, 1, 0]);
  });

  it('should keep the most critical errors up to the limit', () => {
    const lowErrors = Array.from({ length: CONNECTOR_ERRORS_MAX_COUNT }, (_, index) => ({ code: `LOW_${index}`, message: '', criticity: 0 }));
    const criticalError = { code: 'CRITICAL', message: '', criticity: 3 };
    const sanitized = sanitizeConnectorInfoErrors([...lowErrors, criticalError]);
    expect(sanitized).toHaveLength(CONNECTOR_ERRORS_MAX_COUNT);
    expect(sanitized[0]).toEqual(criticalError);
    expect(sanitized[sanitized.length - 1].code).toBe(`LOW_${CONNECTOR_ERRORS_MAX_COUNT - 2}`);
  });

  it('should keep the last report of a repeated code', () => {
    const errors = [
      { code: 'API_UNREACHABLE', message: 'old', criticity: 3 },
      { code: 'RATE_LIMITED', message: '', criticity: 2 },
      { code: 'API_UNREACHABLE', message: 'latest', criticity: 1 },
    ];
    expect(sanitizeConnectorInfoErrors(errors)).toEqual([
      { code: 'RATE_LIMITED', message: '', criticity: 2 },
      { code: 'API_UNREACHABLE', message: 'latest', criticity: 1 },
    ]);
  });

  it('should count a repeated code once against the limit', () => {
    const repeated = Array.from({ length: CONNECTOR_ERRORS_MAX_COUNT }, () => ({ code: 'REPEATED', message: '', criticity: 3 }));
    const distinct = { code: 'DISTINCT', message: '', criticity: 2 };
    expect(sanitizeConnectorInfoErrors([...repeated, distinct]).map(({ code }) => code)).toEqual(['REPEATED', 'DISTINCT']);
  });

  describe('dropped entries logging', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should log each dropped entry at debug level with the connector id', () => {
      const debugSpy = vi.spyOn(logApp, 'debug').mockImplementation(() => {});
      sanitizeConnectorInfoErrors([API_ERROR, { code: '   ', message: 'blank code', criticity: 3 }], 'connector-id');
      expect(debugSpy.mock.calls).toEqual([
        ['[OPENCTI-MODULE] Connector error with a blank code reported on ping, entry dropped', { connectorId: 'connector-id', criticity: 3 }],
      ]);
    });

    it('should not log when every entry is valid', () => {
      const debugSpy = vi.spyOn(logApp, 'debug').mockImplementation(() => {});
      sanitizeConnectorInfoErrors([API_ERROR], 'connector-id');
      expect(debugSpy).not.toHaveBeenCalled();
    });
  });
});

describe('resolveConnectorInfo', () => {
  const connectorInfo = { run_and_terminate: false, buffering: false, queue_threshold: 500, queue_messages_size: 0 };

  it('should add the connector id so errors can be resolved when requested', () => {
    const connector = { internal_id: 'connector-1', connector_info: connectorInfo } as BasicStoreEntityConnector;
    expect(resolveConnectorInfo(connector)).toEqual({ ...connectorInfo, connector_id: 'connector-1' });
  });

  it('should resolve no connector_info for a connector that never sent it', () => {
    expect(resolveConnectorInfo({ internal_id: 'connector-1' } as BasicStoreEntityConnector)).toBeNull();
  });
});
