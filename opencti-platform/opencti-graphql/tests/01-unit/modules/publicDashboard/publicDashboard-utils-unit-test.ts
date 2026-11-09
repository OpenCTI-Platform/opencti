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
  const HOUR = 3600 * 1000;
  const iso = (time: number) => new Date(time).toISOString();
  const monthsBefore = (time: number, months: number) => {
    const date = new Date(time);
    date.setUTCMonth(date.getUTCMonth() - months);
    return date.getTime();
  };

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
    // One bound outside is enough: the whole published range is used.
    expect(resolvePublicDashboardTimeRange(config, { startDate: '2026-02-01T00:00:00.000Z', endDate: '2026-04-30T00:00:00.000Z' }))
      .toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
    expect(resolvePublicDashboardTimeRange(config, {})).toEqual({ startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z' });
  });

  it('should keep the range the public page sends when it lies within the published one', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-03-31T00:00:00.000Z', relativeDate: null };
    // The page sends the dates of the config as it holds them, in any offset
    const sent = { startDate: '2026-01-01T01:00:00+01:00', endDate: '2026-03-31T00:00:00.000Z' };
    expect(resolvePublicDashboardTimeRange(config, sent)).toEqual(sent);
    const narrower = { startDate: '2026-02-01T00:00:00.000Z', endDate: '2026-02-28T00:00:00.000Z' };
    expect(resolvePublicDashboardTimeRange(config, narrower)).toEqual(narrower);
    // Open on one side: an absent bound stays absent
    const openEnd = { startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null };
    expect(resolvePublicDashboardTimeRange(openEnd, { startDate: '2026-06-01T00:00:00.000Z', endDate: null })).toEqual({ startDate: '2026-06-01T00:00:00.000Z', endDate: null });
  });

  it('should compute a relative range frozen at publication back from now', () => {
    const before = Date.now();
    const range = resolvePublicDashboardTimeRange({ relativeDate: 'days-7', startDate: null, endDate: null }, requested);
    const start = new Date(range.startDate as string).getTime();
    const end = new Date(range.endDate as string).getTime();
    expect(end).toBeGreaterThanOrEqual(before);
    expect(end - start).toBeGreaterThanOrEqual(7 * 24 * HOUR - 1000);
    expect(end - start).toBeLessThan(7 * 24 * HOUR + 60 * 1000);
    // An unknown relative date has no start, as in the front, and ends now
    const unknown = resolvePublicDashboardTimeRange({ relativeDate: 'last-week' }, {});
    expect(unknown.startDate).toBeUndefined();
    expect(new Date(unknown.endDate as string).getTime()).toBeGreaterThanOrEqual(before);
  });

  it('should keep the start the public page computes for a relative range, in the time zone of the visitor', () => {
    const now = Date.now();
    // Months and years are counted from the start of the visitor's day: up to one day earlier
    const fromStartOfDay = { startDate: iso(monthsBefore(now, 1) - 20 * HOUR), endDate: iso(now - 1000) };
    expect(resolvePublicDashboardTimeRange({ relativeDate: 'months-1' }, fromStartOfDay)).toEqual(fromStartOfDay);
    const tooEarly = resolvePublicDashboardTimeRange({ relativeDate: 'months-1' }, { startDate: iso(monthsBefore(now, 1) - 30 * HOUR), endDate: iso(now - 1000) });
    expect(new Date(tooEarly.startDate as string).getTime()).toBeGreaterThanOrEqual(monthsBefore(now, 1));
    // Days are counted from now: no more than a daylight saving hour earlier
    const daysSent = { startDate: iso(now - 7 * 24 * HOUR - 30 * 60 * 1000), endDate: iso(now - 1000) };
    expect(resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, daysSent)).toEqual(daysSent);
    const daysTooEarly = resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, { startDate: iso(now - 7 * 24 * HOUR - 2 * HOUR), endDate: iso(now - 1000) });
    expect(new Date(daysTooEarly.startDate as string).getTime()).toBeGreaterThanOrEqual(now - 7 * 24 * HOUR);
    // A page left open: its range falls behind, the current one is used, never a shortened one
    const stale = resolvePublicDashboardTimeRange({ relativeDate: 'days-7' }, { startDate: iso(now - 9 * 24 * HOUR), endDate: iso(now - 2 * 24 * HOUR) });
    expect(new Date(stale.endDate as string).getTime()).toBeGreaterThanOrEqual(now);
  });

  it('should honour any range for a dashboard published without range', () => {
    expect(resolvePublicDashboardTimeRange({}, requested)).toEqual(requested);
    expect(resolvePublicDashboardTimeRange(undefined, {})).toEqual({ startDate: undefined, endDate: undefined });
  });
});
