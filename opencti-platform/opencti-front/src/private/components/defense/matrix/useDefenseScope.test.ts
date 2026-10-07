import { createElement } from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createMockUserContext, testRenderHook } from '../../../../utils/tests/test-render';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useDefenseScope, { defenseScopeStorageKey } from './useDefenseScope';
import { DEFAULT_DEFENSE_SCOPE } from './defenseMatrix-utils';

const mockFetchQuery = vi.fn();
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
}));

const userContext = (id: string) => createMockUserContext({ me: { id } });
const ACME = { value: 'intrusion-set-1', label: 'ACME group', type: 'Intrusion-Set' };
const REVOKED = { value: 'malware-1', label: 'Revoked malware', type: 'Malware' };
const SELECTED_SCOPE = { ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED' as const, threats: [ACME, REVOKED] };

const accessAnswer = (edges: unknown[]) => ({ toPromise: () => Promise.resolve({ stixDomainObjects: { edges } }) });
const ACME_RENAMED = { node: { id: ACME.value, entity_type: ACME.type, representative: { main: 'ACME current name' } } };
const storeScope = (userId: string, scope: unknown) => window.localStorage.setItem(defenseScopeStorageKey(userId), JSON.stringify(scope));
const storedScope = (userId: string) => window.localStorage.getItem(defenseScopeStorageKey(userId));

describe('Hook: useDefenseScope', () => {
  beforeEach(() => {
    window.localStorage.clear();
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue(accessAnswer([]));
  });

  it('should keep the scope of each user under their own key', () => {
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    act(() => {
      hook.result.current[1]({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED', threats: [ACME] });
    });
    // A threat picked by the reader is accessible to them: it needs no confirmation
    expect(hook.result.current[0].threats).toEqual([ACME]);
    expect(hook.result.current[2]).toBe(true);
    expect(storedScope('user-a')).toContain('ACME group');
    expect(mockFetchQuery).not.toHaveBeenCalled();

    const other = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-b') });
    expect(other.hook.result.current[0]).toEqual(DEFAULT_DEFENSE_SCOPE);
  });

  it('should read the scope of the new user when the signed-in user changes without a remount', async () => {
    mockFetchQuery.mockReturnValue(accessAnswer([{ node: { id: ACME.value, entity_type: ACME.type, representative: { main: ACME.label } } }]));
    storeScope('user-a', { ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED', threats: [ACME] });
    let context = userContext('user-a');
    const hook = renderHook(() => useDefenseScope(), {
      wrapper: ({ children }) => createElement(UserContext.Provider, { value: context }, children),
    });
    await waitFor(() => expect(hook.result.current[0].threats).toEqual([ACME]));

    context = userContext('user-b');
    hook.rerender();
    expect(hook.result.current[0]).toEqual(DEFAULT_DEFENSE_SCOPE);
    act(() => {
      hook.result.current[1]({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'ALL' });
    });
    expect(storedScope('user-b')).not.toContain('ACME group');
    expect(storedScope('user-a')).toContain('ACME group');
  });

  it('should drop the scope stored by the first releases for every user of the browser', () => {
    window.localStorage.setItem('defense-matrix-scope', JSON.stringify({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED', threats: [ACME] }));
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    expect(hook.result.current[0]).toEqual(DEFAULT_DEFENSE_SCOPE);
    expect(window.localStorage.getItem('defense-matrix-scope')).toBeNull();
  });

  it('should hand over the stored threats only once the reader is known to access them, with their current names', async () => {
    mockFetchQuery.mockReturnValue(accessAnswer([ACME_RENAMED]));
    storeScope('user-a', SELECTED_SCOPE);
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    // Before the answer, no stored threat is in the scope, which is not ready
    expect(hook.result.current[0].threats).toEqual([]);
    expect(hook.result.current[2]).toBe(false);
    expect(mockFetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      filters: { mode: 'and', filters: [{ key: ['ids'], values: [ACME.value, REVOKED.value] }], filterGroups: [] },
      first: 2,
    }));

    await waitFor(() => expect(hook.result.current[2]).toBe(true));
    // The threat no longer accessible leaves the scope, the other one keeps its current name
    const confirmed = { ...ACME, label: 'ACME current name' };
    expect(hook.result.current[0].threats).toEqual([confirmed]);
    expect(JSON.parse(storedScope('user-a') ?? '{}').threats).toEqual([confirmed]);
    expect(mockFetchQuery).toHaveBeenCalledTimes(1);
  });

  it('should leave the stored threats out of the scope in use when their access cannot be checked', async () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.reject(new Error('unavailable')) });
    storeScope('user-a', SELECTED_SCOPE);
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    await waitFor(() => expect(hook.result.current[2]).toBe(true));
    expect(hook.result.current[0].threats).toEqual([]);

    // Hidden from the reader, they stay stored to be asked again the next time
    act(() => {
      hook.result.current[1]({ ...hook.result.current[0], platformIds: ['platform-1'] });
    });
    expect(hook.result.current[0]).toEqual({ ...SELECTED_SCOPE, platformIds: ['platform-1'], threats: [] });
    expect(JSON.parse(storedScope('user-a') ?? '{}').threats).toEqual([ACME, REVOKED]);
  });

  it('should be ready at once when the stored threats are not selected for the overlay', async () => {
    mockFetchQuery.mockReturnValue(accessAnswer([ACME_RENAMED]));
    storeScope('user-a', { ...SELECTED_SCOPE, threatMode: 'ALL' });
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    expect(hook.result.current[2]).toBe(true);
    expect(hook.result.current[0].threats).toEqual([]);
    await waitFor(() => expect(hook.result.current[0].threats).toEqual([{ ...ACME, label: 'ACME current name' }]));
  });
});
