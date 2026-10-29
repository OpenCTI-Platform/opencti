import { beforeEach, describe, expect, it } from 'vitest';
import {
  dashboardTimeRangeStorageKey,
  parseTimeRangeParam,
  readStoredTimeRange,
  writeStoredTimeRange,
  writeTimeRangeParam,
} from './dashboardTimeRangeStorage';

const key = dashboardTimeRangeStorageKey('user-1', 'ws-1');

describe('dashboard time range storage', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
  });

  it('round-trips a stored range', () => {
    writeStoredTimeRange(key, { startDate: null, endDate: null, relativeDate: 'days-7' });
    expect(readStoredTimeRange(key)).toEqual({ startDate: null, endDate: null, relativeDate: 'days-7' });
    writeStoredTimeRange(key, null);
    expect(window.localStorage.getItem(key)).toBeNull();
  });

  it.each([
    'not json',
    '[]',
    '{"relativeDate":"weeks-2","startDate":null,"endDate":null}',
    '{"relativeDate":"days-7","startDate":"2024-01-01T00:00:00Z","endDate":null}',
    '{"relativeDate":null,"startDate":"2024/01/01","endDate":null}',
  ])('ignores the stored value %s', (raw) => {
    window.localStorage.setItem(key, raw);
    expect(readStoredTimeRange(key)).toBeNull();
  });

  it('round-trips the URL parameter, relative and absolute', () => {
    const absolute = { startDate: '2024-01-01T00:00:00+01:00', endDate: null, relativeDate: null };
    writeTimeRangeParam(absolute);
    expect(parseTimeRangeParam(window.location.search)).toEqual(absolute);
    writeTimeRangeParam({ startDate: null, endDate: null, relativeDate: 'months-3' });
    expect(new URLSearchParams(window.location.search).get('timeRange')).toBe('months-3');
    writeTimeRangeParam(null);
    expect(window.location.search).toBe('');
  });

  it('reads an empty absolute range as no date at all', () => {
    expect(parseTimeRangeParam('?timeRange=..')).toEqual({ startDate: null, endDate: null, relativeDate: null });
  });

  it('keeps the variables parameter when writing the time range', () => {
    window.history.replaceState(null, '', '/?variables=a:b');
    writeTimeRangeParam({ startDate: null, endDate: null, relativeDate: 'days-1' });
    expect(new URLSearchParams(window.location.search).get('variables')).toBe('a:b');
  });

  it.each(['?timeRange=weeks-2', '?timeRange=2024/01/01..', '?timeRange=', '?other=1'])('ignores %s', (search) => {
    expect(parseTimeRangeParam(search)).toBeNull();
  });
});
