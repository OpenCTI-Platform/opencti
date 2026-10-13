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
    window.history.replaceState(null, '', '/'); // navigating to another dashboard drops the query string
    const b = renderHook(() => useDashboardVariables('ws-2', [sector]));
    expect(b.result.current.values.get(sector.id)).toBe('Energy');
  });

  it('isolates two users on the same browser (logout then login)', () => {
    const a = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => a.result.current.setValue(sector.id, 'Finance'));
    a.unmount();
    mocks.userId = 'user-2';
    window.history.replaceState(null, '', '/'); // a new session starts on a fresh URL
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

  it('treats an empty value as unset: default applies now and after a remount', () => {
    const other = { ...country, defaultValue: 'DE' };
    const first = renderHook(() => useDashboardVariables('ws-1', [sector, other]));
    act(() => first.result.current.setValue(sector.id, 'Finance'));
    act(() => first.result.current.setValue(other.id, 'FR'));
    act(() => first.result.current.setValue(sector.id, ''));
    expect(first.result.current.values.get(sector.id)).toBe('Energy');
    expect(JSON.parse(window.localStorage.getItem('dashboard-variables-user-1-ws-1') as string)).toEqual({ [other.id]: 'FR' });
    first.unmount();
    const second = renderHook(() => useDashboardVariables('ws-1', [sector, other]));
    expect(second.result.current.values.get(sector.id)).toBe('Energy');
    expect(second.result.current.values.get(other.id)).toBe('FR');
  });

  it('removes the storage key when the last stored value is unset', () => {
    const first = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => first.result.current.setValue(sector.id, 'Finance'));
    act(() => first.result.current.setValue(sector.id, ''));
    expect(first.result.current.values.get(sector.id)).toBe('Energy');
    expect(window.localStorage.getItem('dashboard-variables-user-1-ws-1')).toBeNull();
    first.unmount();
    const second = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(second.result.current.values.get(sector.id)).toBe('Energy');
  });

  it('does not write to the storage when the feature flag is off', () => {
    mocks.flags = [];
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    expect(window.localStorage.getItem('dashboard-variables-user-1-ws-1')).toBeNull();
    window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [sector.id]: 'Finance' }));
    act(() => result.current.reset());
    expect(window.localStorage.getItem('dashboard-variables-user-1-ws-1')).not.toBeNull();
  });

  it('gives the URL priority over the storage and keeps other query params', () => {
    window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [sector.id]: 'Finance' }));
    window.history.replaceState(null, '', `/?foo=bar&variables=${encodeURIComponent(`${sector.id}:Retail`)}`);
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(result.current.values.get(sector.id)).toBe('Retail');
  });

  it('mirrors a change into the URL without touching other params', () => {
    window.history.replaceState(null, '', '/?foo=bar');
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    const params = new URLSearchParams(window.location.search);
    expect(params.get('foo')).toBe('bar');
    expect(params.get('variables')).toBe(`${sector.id}:Finance`);
  });

  it('never reads nor writes the URL with ignoreLocalValues', () => {
    window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${sector.id}:Retail`)}`);
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector], { ignoreLocalValues: true }));
    expect(result.current.values.get(sector.id)).toBe('Energy');
    act(() => result.current.setValue(sector.id, 'Finance'));
    expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${sector.id}:Retail`);
  });

  it('reset removes the variables param', () => {
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    act(() => result.current.reset());
    expect(new URLSearchParams(window.location.search).has('variables')).toBe(false);
  });

  it('ignores a malformed variables param', () => {
    window.history.replaceState(null, '', '/?variables=%%%');
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(result.current.values.get(sector.id)).toBe('Energy');
  });

  it('ignores a URL value outside the selection pool or of a deleted variable', () => {
    window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${country.id}:US,gone:x`)}`);
    const { result } = renderHook(() => useDashboardVariables('ws-1', [country]));
    expect(result.current.values.get(country.id)).toBe('FR');
    expect([...result.current.values.keys()]).toEqual([country.id]);
  });

  it('keeps URL values of other variables when one variable changes', () => {
    window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${sector.id}:Retail`)}`);
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector, country]));
    act(() => result.current.setValue(country.id, 'DE'));
    expect(result.current.values.get(sector.id)).toBe('Retail');
    expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${sector.id}:Retail,${country.id}:DE`);
  });

  it('does not touch the URL when the feature flag is off', () => {
    mocks.flags = [];
    window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${sector.id}:Retail`)}`);
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${sector.id}:Retail`);
  });
});
