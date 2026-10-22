import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import {
  CONNECTOR_ERROR_CODE_MAX_LENGTH,
  CONNECTOR_ERROR_MESSAGE_MAX_LENGTH,
  CONNECTOR_ERRORS_MAX_COUNT,
  mergeConnectorErrors,
  sanitizeConnectorInfoErrors,
  selectActiveConnectorErrors,
} from '../../../../src/modules/connector/connector-domain';
import { CONNECTOR_ERRORS_TTL_SECONDS } from '../../../../src/modules/connector/connector-redis';
import type { ConnectorInfoError, StoredConnectorInfoError } from '../../../../src/modules/connector/connector-types';

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

  describe('dropped entries logging', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should log each dropped entry with the connector id and the reason', () => {
      const infoSpy = vi.spyOn(logApp, 'info').mockImplementation(() => {});
      const errors = [
        API_ERROR,
        { code: '   ', message: 'blank code', criticity: 0 },
        { code: 'STRING_CRITICITY', message: 'string criticity', criticity: 'HIGH' },
      ] as ConnectorInfoError[];
      sanitizeConnectorInfoErrors(errors, 'connector-id');
      expect(infoSpy.mock.calls).toEqual([
        ['[CONNECTOR] Invalid error reported on ping, entry dropped', { connectorId: 'connector-id', reason: 'blank code', code: '', criticity: 0 }],
        ['[CONNECTOR] Invalid error reported on ping, entry dropped', { connectorId: 'connector-id', reason: 'non-integer criticity', code: 'STRING_CRITICITY', criticity: 'HIGH' }],
      ]);
    });

    it('should not log when every entry is valid', () => {
      const infoSpy = vi.spyOn(logApp, 'info').mockImplementation(() => {});
      sanitizeConnectorInfoErrors([API_ERROR], 'connector-id');
      expect(infoSpy).not.toHaveBeenCalled();
    });
  });
});

const NOW = 1_800_000_000_000;
const TTL_MS = CONNECTOR_ERRORS_TTL_SECONDS * 1000;
const stored = (code: string, criticity: number, ageMs: number, message = ''): StoredConnectorInfoError => ({ code, message, criticity, last_seen_at: NOW - ageMs });

describe('mergeConnectorErrors', () => {
  it('should accumulate errors with distinct codes from successive pings', () => {
    const { kept, removedCodes } = mergeConnectorErrors([stored('FIRST', 1, 1000)], [{ code: 'SECOND', message: '', criticity: 1 }], NOW);
    expect(kept.map(({ code }) => code)).toEqual(['SECOND', 'FIRST']);
    expect(removedCodes).toEqual([]);
  });

  it('should keep the latest report of a code and refresh when it was seen', () => {
    const { kept } = mergeConnectorErrors([stored('API_UNREACHABLE', 1, 1000, 'old message')], [{ code: 'API_UNREACHABLE', message: 'new message', criticity: 3 }], NOW);
    expect(kept).toEqual([{ code: 'API_UNREACHABLE', message: 'new message', criticity: 3, last_seen_at: NOW }]);
  });

  it('should drop errors not reported for 10 minutes', () => {
    const { kept, removedCodes } = mergeConnectorErrors([stored('EXPIRED', 3, TTL_MS), stored('RECENT', 1, TTL_MS - 1)], [{ code: 'NEW', message: '', criticity: 1 }], NOW);
    expect(kept.map(({ code }) => code)).toEqual(['NEW', 'RECENT']);
    expect(removedCodes).toEqual(['EXPIRED']);
  });

  it('should keep the most critical errors up to the limit and remove the others', () => {
    const lowErrors = Array.from({ length: CONNECTOR_ERRORS_MAX_COUNT }, (_, index) => stored(`LOW_${index}`, 0, index + 1));
    const { kept, removedCodes } = mergeConnectorErrors(lowErrors, [{ code: 'CRITICAL', message: '', criticity: 3 }], NOW);
    expect(kept).toHaveLength(CONNECTOR_ERRORS_MAX_COUNT);
    expect(kept[0].code).toBe('CRITICAL');
    expect(removedCodes).toEqual([`LOW_${CONNECTOR_ERRORS_MAX_COUNT - 1}`]);
  });
});

describe('selectActiveConnectorErrors', () => {
  it('should return recent errors sorted by criticity then recency, without the seen date', () => {
    const errors = [stored('EXPIRED', 3, TTL_MS), stored('OLDER', 2, 2000), stored('NEWER', 2, 1000), stored('LOW', 1, 500)];
    expect(selectActiveConnectorErrors(errors, NOW)).toEqual([
      { code: 'NEWER', message: '', criticity: 2 },
      { code: 'OLDER', message: '', criticity: 2 },
      { code: 'LOW', message: '', criticity: 1 },
    ]);
  });
});
