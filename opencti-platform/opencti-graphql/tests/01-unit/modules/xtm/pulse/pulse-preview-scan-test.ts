import { describe, expect, it } from 'vitest';
import { isPulsePreviewPassDue, pulsePreviewNextScan, pulsePreviewPassRange } from '../../../../../src/modules/xtm/pulse/pulse-domain';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-10-04T12:00:00.000Z');
const REFRESHED_AN_HOUR_AGO = new Date(NOW - HOUR).toISOString();

describe('Threat Pulse preview scan', () => {
  it('should run once per refresh interval when the last scan covered the scope', () => {
    expect(isPulsePreviewPassDue({}, NOW, DAY)).toBe(true);
    expect(isPulsePreviewPassDue({ preview_refresh_at: REFRESHED_AN_HOUR_AGO }, NOW, DAY)).toBe(false);
    expect(isPulsePreviewPassDue({ preview_refresh_at: new Date(NOW - DAY).toISOString() }, NOW, DAY)).toBe(true);
    expect(isPulsePreviewPassDue({ preview_refresh_at: REFRESHED_AN_HOUR_AGO }, NOW, DAY, true)).toBe(true);
  });

  it('should go on at every manager cycle while a scan has not covered the scope', () => {
    expect(isPulsePreviewPassDue({ preview_refresh_at: REFRESHED_AN_HOUR_AGO, preview_offset: '1000000' }, NOW, DAY)).toBe(true);
  });

  it('should go on where the scan stopped with the digest day it started with', () => {
    expect(pulsePreviewPassRange({ preview_offset: '1000000', preview_digest_day: '2026-10-04' }, '2026-10-04')).toEqual({ offset: 1000000, scanStart: 0, until: undefined });
  });

  it('should start from the beginning after a covered scan', () => {
    expect(pulsePreviewPassRange({ preview_digest_day: '2026-10-04' }, '2026-10-04')).toEqual({ offset: 0, scanStart: 0, until: undefined });
    expect(pulsePreviewPassRange({}, '2026-10-04')).toEqual({ offset: 0, scanStart: 0, until: undefined });
  });

  it('should keep going when a new digest day overtakes the scan, then cover the start of the scope up to there', () => {
    // The new day starts where the scan stopped.
    const tail = pulsePreviewPassRange({ preview_offset: '1000000', preview_digest_day: '2026-10-03' }, '2026-10-04');
    expect(tail).toEqual({ offset: 1000000, scanStart: 1000000, until: undefined });
    // Not at the end yet: the next pass goes on, the day keeps its start.
    expect(pulsePreviewNextScan(tail, 1000000, false)).toEqual({ preview_offset: '2000000', preview_scan_start: '1000000' });
    // At the end: the scan goes on from the beginning.
    const wrapped = pulsePreviewNextScan(tail, 500000, true);
    expect(wrapped).toEqual({ preview_offset: '0', preview_scan_start: '1000000' });
    const head = pulsePreviewPassRange({ ...wrapped, preview_digest_day: '2026-10-04' }, '2026-10-04');
    expect(head).toEqual({ offset: 0, scanStart: 1000000, until: 1000000 });
    // Up to where the day started: the scope is covered.
    expect(pulsePreviewNextScan(head, 1000000, true)).toEqual({ preview_offset: undefined, preview_scan_start: undefined });
  });

  it('should never restart from the beginning when the digest day changes at every pass', () => {
    let state: { preview_offset?: string; preview_scan_start?: string; preview_digest_day?: string } = { preview_offset: '0', preview_digest_day: '2026-10-01' };
    const days = ['2026-10-02', '2026-10-03', '2026-10-04'];
    days.forEach((day) => {
      const range = pulsePreviewPassRange(state, day);
      state = { ...pulsePreviewNextScan(range, 1000, false), preview_digest_day: day };
    });
    expect(state.preview_offset).toBe('3000');
  });

  it('should cover the whole scope from the start without a new digest day', () => {
    const range = pulsePreviewPassRange({ preview_offset: '1000', preview_digest_day: '2026-10-04' }, '2026-10-04');
    expect(pulsePreviewNextScan(range, 200, true)).toEqual({ preview_offset: undefined, preview_scan_start: undefined });
  });
});
