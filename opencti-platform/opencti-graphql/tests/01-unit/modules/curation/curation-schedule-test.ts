import { describe, expect, it } from 'vitest';
import { isCurationRunning, isOlderThan, nextRunDate } from '../../../../src/modules/curation/curation-schedule';

const DAY = 24 * 3600 * 1000;
const NOW = Date.parse('2026-10-04T02:00:00.000Z');

describe('curation schedule', () => {
  it('is due now when it never ran or when the last run is older than the interval', () => {
    expect(nextRunDate(null, DAY, NOW)).toBe('2026-10-04T02:00:00.000Z');
    expect(nextRunDate('2026-10-02T01:00:00.000Z', DAY, NOW)).toBe('2026-10-04T02:00:00.000Z');
    expect(isOlderThan(undefined, DAY, NOW)).toBe(true);
    expect(isOlderThan('2026-10-03T01:59:59.000Z', DAY, NOW)).toBe(true);
  });

  it('is due one interval after the last run otherwise', () => {
    expect(nextRunDate('2026-10-03T23:30:00.000Z', DAY, NOW)).toBe('2026-10-04T23:30:00.000Z');
    expect(isOlderThan('2026-10-03T23:30:00.000Z', DAY, NOW)).toBe(false);
  });

  it('runs only when both the platform setting and the manager configuration are on', () => {
    expect(isCurationRunning(true, true)).toBe(true);
    expect(isCurationRunning(true, false)).toBe(false);
    expect(isCurationRunning(false, true)).toBe(false);
    expect(isCurationRunning(false, false)).toBe(false);
  });
});
