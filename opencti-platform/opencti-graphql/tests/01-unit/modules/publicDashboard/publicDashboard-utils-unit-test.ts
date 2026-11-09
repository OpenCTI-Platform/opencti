import { describe, expect, it } from 'vitest';
import { resolvePublicDashboardTimeRange, sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('sanitizePublicDashboardUriKey', () => {
  it('should convert a Latin name to a lowercase hyphenated slug', () => {
    expect(sanitizePublicDashboardUriKey('My Dashboard')).toBe('my-dashboard');
  });

  it('should fall back to a UUID v4 when the input contains only non-Latin characters', () => {
    // Japanese name — all characters are stripped by the ASCII-only regex
    const result = sanitizePublicDashboardUriKey('私のダッシュボード');
    expect(result).toMatch(UUID_V4_REGEX);
  });
});

describe('resolvePublicDashboardTimeRange', () => {
  const requested = { startDate: '2020-01-01T00:00:00.000Z', endDate: '2020-12-31T00:00:00.000Z' };

  it('should honour the range of the visitor when the author allowed viewers to edit the time filters', () => {
    const config = { allowViewersToEditTimeFilters: true, startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null };
    expect(resolvePublicDashboardTimeRange(config, requested)).toEqual(requested);
    expect(resolvePublicDashboardTimeRange(config, {})).toEqual({ startDate: undefined, endDate: undefined });
  });

  it('should enforce the absolute range frozen at publication otherwise', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z', relativeDate: null };
    expect(resolvePublicDashboardTimeRange(config, requested)).toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
    // The switch is off by default, and false is not true.
    expect(resolvePublicDashboardTimeRange({ ...config, allowViewersToEditTimeFilters: false }, requested).startDate).toBe('2026-01-01T00:00:00.000Z');
  });

  it('should compute a relative range frozen at publication back from now', () => {
    const before = Date.now();
    const range = resolvePublicDashboardTimeRange({ relativeDate: 'days-7', startDate: null, endDate: null }, requested);
    const start = new Date(range.startDate as string).getTime();
    const end = new Date(range.endDate as string).getTime();
    expect(end).toBeGreaterThanOrEqual(before);
    expect(end - start).toBeGreaterThanOrEqual(7 * 24 * 3600 * 1000 - 1000);
    expect(end - start).toBeLessThan(7 * 24 * 3600 * 1000 + 60 * 1000);
    expect(resolvePublicDashboardTimeRange({ relativeDate: 'last-week' }, requested).startDate).toBeUndefined();
  });

  it('should leave an unbounded range for a dashboard published without any range or config', () => {
    expect(resolvePublicDashboardTimeRange({}, requested)).toEqual({ startDate: undefined, endDate: undefined });
    expect(resolvePublicDashboardTimeRange(undefined, requested)).toEqual({ startDate: undefined, endDate: undefined });
  });
});
