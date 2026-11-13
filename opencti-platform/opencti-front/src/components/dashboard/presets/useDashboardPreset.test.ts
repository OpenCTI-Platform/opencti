import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardPreset } from '../dashboard-types';
import { dashboardPresetStorageKey } from './dashboardPresetStorage';
import { dashboardVariablesStorageKey } from '../dashboardVariablesStorage';
import { dashboardTimeRangeStorageKey } from '../dashboardTimeRangeStorage';

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

  it('applies the preset of the address once the presets of the dashboard are loaded', () => {
    window.history.replaceState(null, '', '/?preset=finance');
    const { result, rerender } = renderHook((current: DashboardPreset[]) => useDashboardPreset('ws-1', current), { initialProps: [] as DashboardPreset[] });
    expect(result.current.activePreset).toBeNull();
    // Meanwhile the address keeps it, so the publication form, which reads it, starts from the same view as the page
    expect(presetParam()).toBe('finance');
    rerender(presets);
    expect(result.current.activePreset?.id).toBe('finance');
  });

  it('shows the default preset for a preset of the address the dashboard does not hold, and leaves the address', () => {
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'energy');
    window.history.replaceState(null, '', '/?preset=gone');
    expect(renderHook(() => useDashboardPreset('ws-1', presets, { defaultPresetId: 'finance' })).result.current.activePreset?.id).toBe('finance');
    expect(presetParam()).toBe('gone');
  });

  it('falls back to the default preset when the stored preset was deleted', () => {
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'gone');
    expect(renderHook(() => useDashboardPreset('ws-1', presets, { defaultPresetId: 'finance' })).result.current.activePreset?.id).toBe('finance');
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset).toBeNull();
  });

  it('drops the values and range kept on another preset when the address names a preset', () => {
    const valuesKey = dashboardVariablesStorageKey('user-1', 'ws-1');
    const rangeKey = dashboardTimeRangeStorageKey('user-1', 'ws-1');
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'energy');
    window.localStorage.setItem(valuesKey, JSON.stringify({ v: 'x' }));
    window.localStorage.setItem(rangeKey, JSON.stringify({ startDate: null, endDate: null, relativeDate: 'days-7' }));
    // The same preset as the stored one: nothing is dropped
    window.history.replaceState(null, '', '/?preset=energy');
    renderHook(() => useDashboardPreset('ws-1', presets));
    expect(window.localStorage.getItem(valuesKey)).not.toBeNull();
    // A preset that does not exist (deleted, mistyped, not loaded yet): nothing is dropped either
    window.history.replaceState(null, '', '/?preset=gone');
    renderHook(() => useDashboardPreset('ws-1', presets));
    expect(window.localStorage.getItem(valuesKey)).not.toBeNull();
    // Another preset: the values and the range of this user go
    window.history.replaceState(null, '', '/?preset=finance');
    renderHook(() => useDashboardPreset('ws-1', presets));
    expect(window.localStorage.getItem(valuesKey)).toBeNull();
    expect(window.localStorage.getItem(rangeKey)).toBeNull();
  });

  it('keeps the preset of the address as the one of this browser, so the changes made on it stay with it', () => {
    window.localStorage.setItem(dashboardPresetStorageKey('user-1', 'ws-1'), 'energy');
    window.history.replaceState(null, '', '/?preset=finance');
    renderHook(() => useDashboardPreset('ws-1', presets));
    expect(window.localStorage.getItem(dashboardPresetStorageKey('user-1', 'ws-1'))).toBe('finance');
    // Opened later without the address, the dashboard shows the same preset
    window.history.replaceState(null, '', '/');
    expect(renderHook(() => useDashboardPreset('ws-1', presets)).result.current.activePreset?.id).toBe('finance');
  });

  it('leaves no preset in the address of a user who may not switch presets', () => {
    window.history.replaceState(null, '', '/?preset=finance&variables=v:x');
    const { result } = renderHook(() => useDashboardPreset('ws-1', presets, { ignoreLocalValues: true, defaultPresetId: 'energy' }));
    expect(result.current.activePreset?.id).toBe('energy');
    expect(presetParam()).toBeNull();
    expect(new URLSearchParams(window.location.search).get('variables')).toBe('v:x');
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
