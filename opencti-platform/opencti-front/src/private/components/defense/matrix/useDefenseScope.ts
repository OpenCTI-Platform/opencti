import { useCallback, useState } from 'react';
import useAuth from '../../../../utils/hooks/useAuth';
import { DefenseScopeState, parseDefenseScope } from './defenseMatrix-utils';

// Unscoped key of the first releases, removed on read: it was shared by every user of the browser.
const LEGACY_DEFENSE_SCOPE_STORAGE_KEY = 'defense-matrix-scope';

/**
 * The scope holds the names of the selected threats: it is stored per user, so that another user
 * of the same browser never reads it.
 */
export const defenseScopeStorageKey = (userId: string) => `${LEGACY_DEFENSE_SCOPE_STORAGE_KEY}-${userId}`;

const readStoredScope = (storageKey: string) => {
  try {
    window.localStorage.removeItem(LEGACY_DEFENSE_SCOPE_STORAGE_KEY);
    return parseDefenseScope(window.localStorage.getItem(storageKey));
  } catch {
    return parseDefenseScope(null);
  }
};

/**
 * Security platforms and threat overlay shared by the defense matrix and the defense gaps backlog,
 * kept across pages and sessions so that both views always show the same scope.
 */
const useDefenseScope = (): [DefenseScopeState, (scope: DefenseScopeState) => void] => {
  const { me } = useAuth();
  const storageKey = defenseScopeStorageKey(me.id);
  // The scope is kept with the key it belongs to: when the signed-in user changes, the scope of the new user is read
  // during the same render, so the threats selected by the previous user are never shown nor written under the new key.
  const [state, setState] = useState<{ storageKey: string; scope: DefenseScopeState }>(() => ({ storageKey, scope: readStoredScope(storageKey) }));
  let current = state;
  if (state.storageKey !== storageKey) {
    current = { storageKey, scope: readStoredScope(storageKey) };
    setState(current);
  }
  const updateScope = useCallback((next: DefenseScopeState) => {
    setState({ storageKey, scope: next });
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(next));
    } catch {
      // Storage can be full or disabled: the scope still applies to the current page.
    }
  }, [storageKey]);
  return [current.scope, updateScope];
};

export default useDefenseScope;
