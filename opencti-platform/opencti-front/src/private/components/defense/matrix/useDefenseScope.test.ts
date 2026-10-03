import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { createMockUserContext, testRenderHook } from '../../../../utils/tests/test-render';
import useDefenseScope, { defenseScopeStorageKey } from './useDefenseScope';
import { DEFAULT_DEFENSE_SCOPE } from './defenseMatrix-utils';

const userContext = (id: string) => createMockUserContext({ me: { id } });
const ACME = { value: 'intrusion-set-1', label: 'ACME group', type: 'Intrusion-Set' };

describe('Hook: useDefenseScope', () => {
  beforeEach(() => window.localStorage.clear());

  it('should keep the scope of each user under their own key', () => {
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    act(() => {
      hook.result.current[1]({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED', threats: [ACME] });
    });
    expect(hook.result.current[0].threats).toEqual([ACME]);
    expect(window.localStorage.getItem(defenseScopeStorageKey('user-a'))).toContain('ACME group');

    const other = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-b') });
    expect(other.hook.result.current[0]).toEqual(DEFAULT_DEFENSE_SCOPE);
  });

  it('should drop the scope stored by the first releases for every user of the browser', () => {
    window.localStorage.setItem('defense-matrix-scope', JSON.stringify({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED', threats: [ACME] }));
    const { hook } = testRenderHook(() => useDefenseScope(), { userContext: userContext('user-a') });
    expect(hook.result.current[0]).toEqual(DEFAULT_DEFENSE_SCOPE);
    expect(window.localStorage.getItem('defense-matrix-scope')).toBeNull();
  });
});
