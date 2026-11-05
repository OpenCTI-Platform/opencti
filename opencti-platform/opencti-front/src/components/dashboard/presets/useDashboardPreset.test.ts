import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardPreset } from '../dashboard-types';
import { dashboardPresetStorageKey } from './dashboardPresetStorage';

const mocks = vi.hoisted(() => ({ userId: 'user-1' }));
vi.mock('../../../utils/hooks/useAuth', () => ({ default: () => ({ me: { id: mocks.userId } }) }));

import { useDashboardPreset } from './useDashboardPreset';

const range = { startDate: null, endDate: null, relativeDate: null };
const presets: DashboardPreset[] = [
  { id: 'energy', name: 'Energy', values: {}, config: range },
  { id: 'finance', name: 'Finance', values: {}, config: range },
];
const presetParam = () => new URLSearchParams(window.location.search).get('preset');

describe('useDashboardPreset', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    mocks.userId = 'user-1';
  });

  it('starts without preset, or on the default preset of the user', () => {
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset).toBeNull();
    const withDefault = renderHook(() => useDashboardPreset('ws-1', presets, { defaultPresetId: 'finance' }));
    expect(withDefault.result.current.activePreset?.id).toBe('finance');
    expect(withDefault.result.current.defaultPreset?.id).toBe('finance');
    // An unknown default preset is ignored
    expect(renderHook(() => useDashboardPreset('ws-1', presets, { defaultPresetId: 'gone' })).result.current.activePreset).toBeNull();
  });

  it('persists the selection, reflects it in the URL, and finds it again after a remount', () => {
    const first = renderHook(() => useDashboardPreset('ws-1', presets));
    act(() => first.result.current.select('energy'));
    expect(first.result.current.activePreset?.id).toBe('energy');
    expect(presetParam()).toBe('energy');
    first.unmount();
    window.history.replaceState(null, '', '/');
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset?.id).toBe('energy');
  });

  it('prefers the URL over the stored preset and ignores a deleted one', () => {
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'energy');
    window.history.replaceState(null, '', '/?preset=finance');
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset?.id).toBe('finance');
    window.history.replaceState(null, '', '/?preset=gone');
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset).toBeNull();
  });

  it('isolates two dashboards and two users, and reads nothing local when asked to', () => {
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'energy');
    expect(renderHook(() => useDashboardPreset('ws-2', presets)).result.current.activePreset).toBeNull();
    expect(renderHook(() => useDashboardPreset('ws-1', presets, { ignoreLocalValues: true })).result.current.activePreset).toBeNull();
    mocks.userId = 'user-2';
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset).toBeNull();
  });

  it('selecting the default preset or none keeps nothing local', () => {
    const { result } = renderHook(() => useDashboardPreset('ws-1', presets, { defaultPresetId: 'finance' }));
    act(() => result.current.select('energy'));
    expect(window.localStorage.getItem(dashboardPresetStorageKey('user-1', 'ws-1'))).toBe('energy');
    act(() => result.current.select('finance'));
    expect(window.localStorage.getItem(dashboardPresetStorageKey('user-1', 'ws-1'))).toBeNull();
    expect(result.current.activePreset?.id).toBe('finance');
    act(() => result.current.select(null));
    expect(result.current.activePreset?.id).toBe('finance');
    expect(presetParam()).toBeNull();
  });
});
