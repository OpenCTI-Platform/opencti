import { describe, expect, it } from 'vitest';
import type { DashboardConfig } from './dashboard-types';
import { applyDateChange, isSameTimeRange, pickTimeRange } from './dashboardTimeRange';

const empty = { startDate: null, endDate: null, relativeDate: null };

describe('applyDateChange', () => {
  it('maps none to null', () => {
    expect(applyDateChange({ ...empty, relativeDate: 'days-7' }, 'relativeDate', 'none')).toEqual(empty);
  });

  it('clears the absolute dates when a relative date is picked', () => {
    expect(applyDateChange({ startDate: '2024-01-01T00:00:00Z', endDate: '2024-02-01T00:00:00Z', relativeDate: null }, 'relativeDate', 'months-1'))
      .toEqual({ ...empty, relativeDate: 'months-1' });
  });

  it('keeps the absolute dates when the relative date is set to none', () => {
    const range = { startDate: '2024-01-01T00:00:00Z', endDate: null, relativeDate: 'days-1' };
    expect(applyDateChange(range, 'relativeDate', 'none')).toEqual({ ...range, relativeDate: null });
  });

  it('changes one absolute date only', () => {
    expect(applyDateChange(empty, 'startDate', '2024-01-01T00:00:00Z')).toEqual({ ...empty, startDate: '2024-01-01T00:00:00Z' });
  });

  it('keeps the other keys of a dashboard config, and adds no missing date key', () => {
    const config: DashboardConfig = { refresh_interval: 5 };
    expect(applyDateChange(config, 'endDate', '2024-01-01T00:00:00Z'))
      .toEqual({ refresh_interval: 5, endDate: '2024-01-01T00:00:00Z' });
  });
});

describe('pickTimeRange', () => {
  it('reads a config with missing keys as nulls, ignoring the other keys', () => {
    expect(pickTimeRange({ relativeDate: 'days-7', refresh_interval: 5, allowViewersToChangeVariables: true }))
      .toEqual({ ...empty, relativeDate: 'days-7' });
    expect(pickTimeRange(undefined)).toEqual(empty);
  });
});

describe('isSameTimeRange', () => {
  it('compares two ranges field by field', () => {
    expect(isSameTimeRange(empty, { ...empty })).toBe(true);
    expect(isSameTimeRange(empty, { ...empty, endDate: '2024-01-01T00:00:00Z' })).toBe(false);
  });
});
