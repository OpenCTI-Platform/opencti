import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardConfig } from './dashboard-types';
import { dashboardTimeRangeStorageKey } from './dashboardTimeRangeStorage';

const mocks = vi.hoisted(() => ({ userId: 'user-1', flags: ['DASHBOARD_VARIABLES'] as string[] }));
vi.mock('../../utils/hooks/useAuth', () => ({ default: () => ({ me: { id: mocks.userId } }) }));
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (f: string) => mocks.flags.includes(f) }),
}));

import { useDashboardTimeRange } from './useDashboardTimeRange';

const config: DashboardConfig = { relativeDate: 'days-7', startDate: null, endDate: null };
const relative = (relativeDate: string) => ({ startDate: null, endDate: null, relativeDate });
const store = (userId: string, workspaceId: string, relativeDate: string) => window.localStorage.setItem(
  dashboardTimeRangeStorageKey(userId, workspaceId),
  JSON.stringify(relative(relativeDate)),
);
const timeRangeParam = () => new URLSearchParams(window.location.search).get('timeRange');

describe('useDashboardTimeRange', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    mocks.userId = 'user-1';
    mocks.flags = ['DASHBOARD_VARIABLES'];
  });

  it('starts from the manifest range', () => {
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config));
    expect(result.current.range.relativeDate).toBe('days-7');
    expect(result.current.isModified).toBe(false);
  });

  it('persists a change, reflects it in the URL, and finds it again after a remount', () => {
    const first = renderHook(() => useDashboardTimeRange('ws-1', config));
    act(() => first.result.current.setDate('relativeDate', 'months-1'));
    expect(first.result.current.isModified).toBe(true);
    expect(timeRangeParam()).toBe('months-1');
    first.unmount();
    window.history.replaceState(null, '', '/');
    expect(renderHook(() => useDashboardTimeRange('ws-1', config)).result.current.range.relativeDate).toBe('months-1');
  });

  it('prefers the URL over the stored range', () => {
    store('user-1', 'ws-1', 'months-1');
    window.history.replaceState(null, '', '/?timeRange=years-1');
    expect(renderHook(() => useDashboardTimeRange('ws-1', config)).result.current.range.relativeDate).toBe('years-1');
  });

  it('isolates two dashboards and two users', () => {
    store('user-1', 'ws-1', 'months-1');
    expect(renderHook(() => useDashboardTimeRange('ws-2', config)).result.current.range.relativeDate).toBe('days-7');
    mocks.userId = 'user-2';
    expect(renderHook(() => useDashboardTimeRange('ws-1', config)).result.current.range.relativeDate).toBe('days-7');
  });

  it('drops the local entry when a change comes back to the default', () => {
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config));
    act(() => result.current.setDate('relativeDate', 'months-1'));
    act(() => result.current.setDate('relativeDate', 'days-7'));
    expect(result.current.isModified).toBe(false);
    expect(window.localStorage.getItem(dashboardTimeRangeStorageKey('user-1', 'ws-1'))).toBeNull();
    expect(timeRangeParam()).toBeNull();
  });

  it('is not modified when the manifest default catches up with the local range', () => {
    store('user-1', 'ws-1', 'months-1');
    const { result, rerender } = renderHook((current: DashboardConfig) => useDashboardTimeRange('ws-1', current), { initialProps: config });
    expect(result.current.isModified).toBe(true);
    rerender({ ...config, relativeDate: 'months-1' });
    expect(result.current.isModified).toBe(false);
  });

  it('reads and writes nothing when local values are ignored', () => {
    store('user-1', 'ws-1', 'months-1');
    window.history.replaceState(null, '', '/?timeRange=years-1');
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config, { ignoreLocalValues: true }));
    expect(result.current.range.relativeDate).toBe('days-7');
    act(() => result.current.setDate('relativeDate', 'months-6'));
    expect(result.current.range.relativeDate).toBe('days-7');
    expect(timeRangeParam()).toBe('years-1');
    expect(window.localStorage.getItem(dashboardTimeRangeStorageKey('user-1', 'ws-1'))).toBe(JSON.stringify(relative('months-1')));
  });

  it('reads and writes nothing when the flag is off', () => {
    mocks.flags = [];
    store('user-1', 'ws-1', 'months-1');
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config));
    expect(result.current.range.relativeDate).toBe('days-7');
    act(() => result.current.setDate('relativeDate', 'months-6'));
    expect(result.current.range.relativeDate).toBe('days-7');
    expect(timeRangeParam()).toBeNull();
  });

  it('resetRange drops the submitted range only, and keeps a range changed since', () => {
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config));
    act(() => result.current.setDate('relativeDate', 'months-1'));
    const submitted = result.current.range;
    act(() => result.current.setDate('relativeDate', 'years-1'));
    act(() => result.current.resetRange(submitted));
    expect(result.current.range.relativeDate).toBe('years-1');
    act(() => result.current.resetRange(relative('years-1')));
    expect(result.current.range.relativeDate).toBe('days-7');
    expect(window.localStorage.getItem(dashboardTimeRangeStorageKey('user-1', 'ws-1'))).toBeNull();
  });

  it('reset clears the storage and the URL', () => {
    const { result } = renderHook(() => useDashboardTimeRange('ws-1', config));
    act(() => result.current.setDate('relativeDate', 'none'));
    act(() => result.current.setDate('startDate', '2024-01-01T00:00:00Z'));
    expect(timeRangeParam()).toBe('2024-01-01T00:00:00Z..');
    act(() => result.current.reset());
    expect(result.current.range).toEqual(relative('days-7'));
    expect(timeRangeParam()).toBeNull();
    expect(window.localStorage.getItem(dashboardTimeRangeStorageKey('user-1', 'ws-1'))).toBeNull();
  });
});
