import { useCallback, useState } from 'react';
import { DefenseScopeState, parseDefenseScope } from './defenseMatrix-utils';

const DEFENSE_SCOPE_STORAGE_KEY = 'defense-matrix-scope';

const readStoredScope = () => {
  try {
    return parseDefenseScope(window.localStorage.getItem(DEFENSE_SCOPE_STORAGE_KEY));
  } catch {
    return parseDefenseScope(null);
  }
};

/**
 * Security platforms and threat overlay shared by the defense matrix and the defense gaps backlog,
 * kept across pages and sessions so that both views always show the same scope.
 */
const useDefenseScope = (): [DefenseScopeState, (scope: DefenseScopeState) => void] => {
  const [scope, setScope] = useState<DefenseScopeState>(readStoredScope);
  const updateScope = useCallback((next: DefenseScopeState) => {
    setScope(next);
    try {
      window.localStorage.setItem(DEFENSE_SCOPE_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Storage can be full or disabled: the scope still applies to the current page.
    }
  }, []);
  return [scope, updateScope];
};

export default useDefenseScope;
