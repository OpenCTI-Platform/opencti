import { describe, expect, it } from 'vitest';
import { isPulsePreviewPassDue, pulsePreviewPassOffset } from '../../../../../src/modules/xtm/pulse/pulse-domain';

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
    expect(pulsePreviewPassOffset({ preview_offset: '1000000', preview_digest_day: '2026-10-04' }, '2026-10-04')).toBe(1000000);
  });

  it('should start over when a new digest day overtakes the scan, and after a covered scan', () => {
    expect(pulsePreviewPassOffset({ preview_offset: '1000000', preview_digest_day: '2026-10-03' }, '2026-10-04')).toBe(0);
    expect(pulsePreviewPassOffset({ preview_digest_day: '2026-10-04' }, '2026-10-04')).toBe(0);
    expect(pulsePreviewPassOffset({}, '2026-10-04')).toBe(0);
  });
});
