import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardVariable } from './dashboard-types';

const mocks = vi.hoisted(() => ({ userId: 'user-1', flags: ['DASHBOARD_VARIABLES'] as string[] }));
vi.mock('../../utils/hooks/useAuth', () => ({ default: () => ({ me: { id: mocks.userId } }) }));
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (f: string) => mocks.flags.includes(f) }),
}));

import { useDashboardVariables } from './useDashboardVariables';

const sector: DashboardVariable = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Sector', type: 'text',
  restriction: { mode: 'none' }, defaultValue: 'Energy',
};
const country: DashboardVariable = {
  id: '22222222-2222-4222-8222-222222222222', name: 'Country', type: 'text',
  restriction: { mode: 'selection', values: ['FR', 'DE'] }, defaultValue: 'FR',
};

describe('useDashboardVariables', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
    mocks.userId = 'user-1';
    mocks.flags = ['DASHBOARD_VARIABLES'];
  });

  it('starts from the manifest defaults', () => {
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(result.current.values.get(sector.id)).toBe('Energy');
    expect(result.current.isModified).toBe(false);
  });

  it('persists a value and finds it again after a remount', () => {
    const first = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => first.result.current.setValue(sector.id, 'Finance'));
    first.unmount();
    const second = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(second.result.current.values.get(sector.id)).toBe('Finance');
    expect(second.result.current.isModified).toBe(true);
  });

  it('isolates two dashboards', () => {
    const a = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => a.result.current.setValue(sector.id, 'Finance'));
    const b = renderHook(() => useDashboardVariables('ws-2', [sector]));
    expect(b.result.current.values.get(sector.id)).toBe('Energy');
  });

  it('isolates two users on the same browser (logout then login)', () => {
    const a = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => a.result.current.setValue(sector.id, 'Finance'));
    a.unmount();
    mocks.userId = 'user-2';
    const b = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(b.result.current.values.get(sector.id)).toBe('Energy');
  });

  it('reset restores the defaults and empties the storage entry', () => {
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    act(() => result.current.reset());
    expect(result.current.values.get(sector.id)).toBe('Energy');
    expect(window.localStorage.getItem('dashboard-variables-user-1-ws-1')).toBeNull();
  });

  it('ignores a stored value of a variable that no longer exists', () => {
    window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ gone: 'x' }));
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect([...result.current.values.keys()]).toEqual([sector.id]);
  });

  it('ignores a stored value outside the selection pool', () => {
    window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [country.id]: 'US' }));
    const { result } = renderHook(() => useDashboardVariables('ws-1', [country]));
    expect(result.current.values.get(country.id)).toBe('FR');
  });

  it('ignoreLocalValues returns the manifest values even when the storage is populated', () => {
    window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [sector.id]: 'Finance' }));
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector], { ignoreLocalValues: true }));
    expect(result.current.values.get(sector.id)).toBe('Energy');
  });

  it('returns an empty map when the feature flag is off', () => {
    mocks.flags = [];
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(result.current.values.size).toBe(0);
  });

  it('keeps the same Map instance when the manifest is re-saved with identical content', () => {
    const { result, rerender } = renderHook(({ vars }) => useDashboardVariables('ws-1', vars), { initialProps: { vars: [sector] } });
    const before = result.current.values;
    rerender({ vars: [{ ...sector }] });
    expect(result.current.values).toBe(before);
  });
});
