import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('starts from the manifest defaults', () => {
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(result.current.values.get(sector.id)).toBe('Energy');
  });

  it('persists a value and finds it again after a remount', () => {
    const first = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => first.result.current.setValue(sector.id, 'Finance'));
    first.unmount();
    const second = renderHook(() => useDashboardVariables('ws-1', [sector]));
    expect(second.result.current.values.get(sector.id)).toBe('Finance');
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

  describe('resetValues', () => {
    const other = { ...country, defaultValue: 'FR' };
    const STORAGE_KEY = 'dashboard-variables-user-1-ws-1';

    it('drops only the given values from the storage and the URL, and keeps the others', () => {
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector, other]));
      act(() => result.current.setValue(sector.id, 'Finance'));
      act(() => result.current.setValue(other.id, 'DE'));
      act(() => result.current.resetValues(new Map([[sector.id, 'Finance']])));
      expect(result.current.values.get(sector.id)).toBe('Energy');
      expect(result.current.values.get(other.id)).toBe('DE');
      expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) as string)).toEqual({ [other.id]: 'DE' });
      expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${other.id}:DE`);
    });

    it('removes the storage key and the URL param when nothing else is left', () => {
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
      act(() => result.current.setValue(sector.id, 'Finance'));
      act(() => result.current.resetValues(new Map([[sector.id, 'Finance']])));
      expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
      expect(new URLSearchParams(window.location.search).has('variables')).toBe(false);
    });

    it('keeps a value that is not the given one any more, even when called from a stale closure', () => {
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector, other]));
      act(() => result.current.setValue(sector.id, 'Finance'));
      act(() => result.current.setValue(other.id, 'DE'));
      // What an asynchronous action captured when it started.
      const staleResetValues = result.current.resetValues;
      const submitted = result.current.values;
      act(() => result.current.setValue(sector.id, 'Retail'));
      act(() => staleResetValues(submitted));
      expect(result.current.values.get(sector.id)).toBe('Retail');
      expect(result.current.values.get(other.id)).toBe('FR');
      expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) as string)).toEqual({ [sector.id]: 'Retail' });
    });

    it('does nothing with ignoreLocalValues nor when the feature flag is off', () => {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ [sector.id]: 'Finance' }));
      const ignoring = renderHook(() => useDashboardVariables('ws-1', [sector], { ignoreLocalValues: true }));
      act(() => ignoring.result.current.resetValues(new Map([[sector.id, 'Finance']])));
      mocks.flags = [];
      const disabled = renderHook(() => useDashboardVariables('ws-1', [sector]));
      act(() => disabled.result.current.resetValues(new Map([[sector.id, 'Finance']])));
      expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) as string)).toEqual({ [sector.id]: 'Finance' });
    });
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

  it('still updates the values when the storage write throws', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Quota exceeded', 'QuotaExceededError');
    });
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector, country]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    expect(result.current.values.get(sector.id)).toBe('Finance');
    // The in-memory state is the source for the session: the next change keeps the previous one.
    act(() => result.current.setValue(country.id, 'DE'));
    expect(result.current.values.get(sector.id)).toBe('Finance');
    expect(result.current.values.get(country.id)).toBe('DE');
  });

  it('still updates the values when the URL write throws', () => {
    vi.spyOn(window.history, 'replaceState').mockImplementation(() => {
      throw new DOMException('Too many calls', 'SecurityError');
    });
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    expect(result.current.values.get(sector.id)).toBe('Finance');
    expect(JSON.parse(window.localStorage.getItem('dashboard-variables-user-1-ws-1') as string)).toEqual({ [sector.id]: 'Finance' });
  });

  it('still resets when the storage write throws', () => {
    const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
    act(() => result.current.setValue(sector.id, 'Finance'));
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new DOMException('Denied', 'SecurityError');
    });
    act(() => result.current.reset());
    expect(result.current.values.get(sector.id)).toBe('Energy');
  });

  describe('type validation of the stored and URL values', () => {
    const flag: DashboardVariable = { id: '33333333-3333-4333-8333-333333333333', name: 'Flag', type: 'boolean', restriction: { mode: 'none' }, defaultValue: 'true' };
    const size: DashboardVariable = { id: '44444444-4444-4444-8444-444444444444', name: 'Size', type: 'numeric', restriction: { mode: 'none' }, defaultValue: '10' };
    const since: DashboardVariable = { id: '55555555-5555-4555-8555-555555555555', name: 'Since', type: 'date', restriction: { mode: 'none' }, defaultValue: '2024-01-01T00:00:00.000Z' };
    const all = [flag, size, since];
    const invalid = { [flag.id]: 'banana', [size.id]: 'abc', [since.id]: 'not a date' };
    const valid = { [flag.id]: 'false', [size.id]: '42', [since.id]: '2024-06-01T00:00:00.000Z' };

    it('falls back to the defaults for invalid values of the storage', () => {
      window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify(invalid));
      const { result } = renderHook(() => useDashboardVariables('ws-1', all));
      expect(Object.fromEntries(result.current.values)).toEqual({ [flag.id]: 'true', [size.id]: '10', [since.id]: '2024-01-01T00:00:00.000Z' });
    });

    it('falls back to the defaults for invalid values of the URL', () => {
      const param = Object.entries(invalid).map(([id, value]) => `${id}:${encodeURIComponent(value)}`).join(',');
      window.history.replaceState(null, '', `/?variables=${encodeURIComponent(param)}`);
      const { result } = renderHook(() => useDashboardVariables('ws-1', all));
      expect(Object.fromEntries(result.current.values)).toEqual({ [flag.id]: 'true', [size.id]: '10', [since.id]: '2024-01-01T00:00:00.000Z' });
    });

    it('applies the valid values of the storage and of the URL', () => {
      window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [flag.id]: 'false', [size.id]: '42' }));
      window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${since.id}:${encodeURIComponent(valid[since.id])}`)}`);
      const { result } = renderHook(() => useDashboardVariables('ws-1', all));
      expect(Object.fromEntries(result.current.values)).toEqual(valid);
    });

    it('ignores a stored text value referencing another variable', () => {
      window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ [sector.id]: `$var:${country.id}` }));
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
      expect(result.current.values.get(sector.id)).toBe('Energy');
    });
  });

  describe('local values that stop being ignored', () => {
    const storageKey = 'dashboard-variables-user-1-ws-1';
    const seed = () => {
      window.localStorage.setItem(storageKey, JSON.stringify({ [sector.id]: 'Finance' }));
      window.history.replaceState(null, '', `/?variables=${encodeURIComponent(`${country.id}:DE`)}`);
    };
    const render = (initial: boolean) => renderHook(
      ({ ignore }) => useDashboardVariables('ws-1', [sector, country], { ignoreLocalValues: ignore }),
      { initialProps: { ignore: initial } },
    );

    it('applies the stored and URL values once they stop being ignored, and keeps them on the next write', () => {
      seed();
      const { result, rerender } = render(true);
      expect(result.current.values.get(sector.id)).toBe('Energy');
      expect(result.current.values.get(country.id)).toBe('FR');
      rerender({ ignore: false });
      expect(result.current.values.get(sector.id)).toBe('Finance');
      expect(result.current.values.get(country.id)).toBe('DE');
      act(() => result.current.setValue(sector.id, 'Retail'));
      expect(JSON.parse(window.localStorage.getItem(storageKey) as string)).toEqual({ [sector.id]: 'Retail', [country.id]: 'DE' });
    });

    it('goes back to the defaults, writing nothing, when the values are ignored again', () => {
      seed();
      const { result, rerender } = render(false);
      expect(result.current.values.get(sector.id)).toBe('Finance');
      rerender({ ignore: true });
      expect(result.current.values.get(sector.id)).toBe('Energy');
      expect(result.current.values.get(country.id)).toBe('FR');
      act(() => result.current.setValue(sector.id, 'Retail'));
      expect(JSON.parse(window.localStorage.getItem(storageKey) as string)).toEqual({ [sector.id]: 'Finance' });
      expect(new URLSearchParams(window.location.search).get('variables')).toBe(`${country.id}:DE`);
    });

    it('keeps the state stable between renders once resynchronised', () => {
      seed();
      const { result, rerender } = render(true);
      rerender({ ignore: false });
      const before = result.current.values;
      window.localStorage.setItem(storageKey, JSON.stringify({ [sector.id]: 'Other' }));
      rerender({ ignore: false });
      expect(result.current.values).toBe(before);
      expect(result.current.values.get(sector.id)).toBe('Finance');
    });

    it('applies the stored values when the feature flag resolves after the mount', () => {
      mocks.flags = [];
      seed();
      const { result, rerender } = render(false);
      expect(result.current.values.size).toBe(0);
      mocks.flags = ['DASHBOARD_VARIABLES'];
      rerender({ ignore: false });
      expect(result.current.values.get(sector.id)).toBe('Finance');
      expect(result.current.values.get(country.id)).toBe('DE');
    });
  });

  describe('deleted variables', () => {
    const urlValues = () => new URLSearchParams(window.location.search).get('variables');
    const storedValues = () => JSON.parse(window.localStorage.getItem('dashboard-variables-user-1-ws-1') as string);

    it('drops the entry of a deleted variable at the next write, from the storage and from the URL', () => {
      window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ gone: 'x', [sector.id]: 'Finance' }));
      window.history.replaceState(null, '', `/?variables=${encodeURIComponent('other-gone:y')}`);
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector, country]));
      act(() => result.current.setValue(country.id, 'DE'));
      expect(storedValues()).toEqual({ [sector.id]: 'Finance', [country.id]: 'DE' });
      expect(urlValues()).toBe(`${sector.id}:Finance,${country.id}:DE`);
    });

    it('does not persist the value of a variable deleted while the page is open', () => {
      const { result, rerender } = renderHook(({ vars }) => useDashboardVariables('ws-1', vars), { initialProps: { vars: [sector, country] } });
      act(() => result.current.setValue(country.id, 'DE'));
      rerender({ vars: [sector] });
      act(() => result.current.setValue(sector.id, 'Finance'));
      expect(storedValues()).toEqual({ [sector.id]: 'Finance' });
      expect(urlValues()).toBe(`${sector.id}:Finance`);
    });

    it('removes the storage key and the URL param when only deleted entries remained', () => {
      window.localStorage.setItem('dashboard-variables-user-1-ws-1', JSON.stringify({ gone: 'x' }));
      const { result } = renderHook(() => useDashboardVariables('ws-1', [sector]));
      act(() => result.current.setValue(sector.id, ''));
      expect(window.localStorage.getItem('dashboard-variables-user-1-ws-1')).toBeNull();
      expect(urlValues()).toBeNull();
    });
  });
});
