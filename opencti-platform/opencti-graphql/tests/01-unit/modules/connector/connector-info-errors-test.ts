import { describe, expect, it } from 'vitest';
import {
  CONNECTOR_ERROR_CODE_MAX_LENGTH,
  CONNECTOR_ERROR_MESSAGE_MAX_LENGTH,
  CONNECTOR_ERRORS_MAX_COUNT,
  sanitizeConnectorInfoErrors,
} from '../../../../src/modules/connector/connector-domain';
import type { ConnectorInfoError } from '../../../../src/modules/connector/connector-types';

const API_ERROR: ConnectorInfoError = { code: 'API_UNREACHABLE', message: 'Source API returned 503', criticity: 2 };

describe('sanitizeConnectorInfoErrors', () => {
  it('should return an empty list for missing errors', () => {
    expect(sanitizeConnectorInfoErrors(undefined)).toEqual([]);
    expect(sanitizeConnectorInfoErrors(null)).toEqual([]);
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

  it('should not split a surrogate pair when truncating', () => {
    const [error] = sanitizeConnectorInfoErrors([{ code: 'EMOJI', message: '🔥'.repeat(2000), criticity: 0 }]);
    expect(error.message).toBe('🔥'.repeat(CONNECTOR_ERROR_MESSAGE_MAX_LENGTH));
  });

  it('should drop errors with a blank code or a non-integer criticity', () => {
    const errors = [
      API_ERROR,
      { code: '   ', message: 'blank code', criticity: 0 },
      { code: 'NO_CRITICITY', message: 'missing criticity' },
      { code: 'STRING_CRITICITY', message: 'string criticity', criticity: 'HIGH' },
      { code: 'DECIMAL_CRITICITY', message: 'decimal criticity', criticity: 1.5 },
      { code: null, message: 'null code', criticity: 0 },
    ] as ConnectorInfoError[];
    expect(sanitizeConnectorInfoErrors(errors)).toEqual([API_ERROR]);
  });

  it('should sort errors from the most to the least critical', () => {
    const criticities = [1, 3, 0, 2];
    const errors = criticities.map((criticity) => ({ code: `CRITICITY_${criticity}`, message: '', criticity }));
    expect(sanitizeConnectorInfoErrors(errors).map(({ criticity }) => criticity)).toEqual([
      3,
      2,
      1,
      0,
    ]);
  });

  it('should keep the most critical errors up to the limit', () => {
    const lowErrors = Array.from({ length: CONNECTOR_ERRORS_MAX_COUNT }, (_, index) => ({ code: `LOW_${index}`, message: '', criticity: 0 }));
    const criticalError = { code: 'CRITICAL', message: '', criticity: 3 };
    const sanitized = sanitizeConnectorInfoErrors([...lowErrors, criticalError]);
    expect(sanitized).toHaveLength(CONNECTOR_ERRORS_MAX_COUNT);
    expect(sanitized[0]).toEqual(criticalError);
    expect(sanitized[sanitized.length - 1].code).toBe(`LOW_${CONNECTOR_ERRORS_MAX_COUNT - 2}`);
  });
});
