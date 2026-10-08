import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { fetchQuery } from '../../../../relay/environment';
import { DEFENSE_MAX_SELECTED_THREATS, DEFENSE_THREAT_TYPES, type DefenseScopeState, type DefenseThreatOption, parseDefenseScope } from './defenseMatrix-utils';
import { useDefenseScopeThreatsQuery$data } from './__generated__/useDefenseScopeThreatsQuery.graphql';

// Unscoped key of the first releases, removed on read: it was shared by every user of the browser.
const LEGACY_DEFENSE_SCOPE_STORAGE_KEY = 'defense-matrix-scope';

const NO_IDS: ReadonlySet<string> = new Set();

const defenseScopeThreatsQuery = graphql`
  query useDefenseScopeThreatsQuery($types: [String], $filters: FilterGroup, $first: Int) {
    stixDomainObjects(types: $types, filters: $filters, first: $first) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

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

const writeStoredScope = (storageKey: string, scope: DefenseScopeState) => {
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(scope));
  } catch {
    // Storage can be full or disabled: the scope still applies to the current page.
  }
};

interface StoredScope {
  storageKey: string;
  scope: DefenseScopeState;
  // The threats the reader is known to access: picked from their own search, or confirmed by the access query
  confirmedIds: ReadonlySet<string>;
  // The access to the stored threats was asked, answered or failed
  checked: boolean;
}

const readScope = (storageKey: string): StoredScope => ({ storageKey, scope: readStoredScope(storageKey), confirmedIds: NO_IDS, checked: false });

/**
 * Security platforms and threat overlay shared by the defense matrix and the defense gaps backlog,
 * kept across pages and sessions so that both views always show the same scope.
 *
 * A stored threat reaches no query nor view before the reader is known to access it: one query confirms the stored
 * threats, drops the ones no longer accessible and refreshes the names. Until it answers, a scope of selected threats
 * is not ready; a failed answer leaves the stored threats out of the scope in use, and they are asked again the next time.
 */
const useDefenseScope = (): [DefenseScopeState, (scope: DefenseScopeState) => void, boolean] => {
  const { me } = useAuth();
  const storageKey = defenseScopeStorageKey(me.id);
  // The scope is kept with the key it belongs to: when the signed-in user changes, the scope of the new user is read
  // during the same render, so the threats selected by the previous user are never shown nor written under the new key.
  const [state, setState] = useState<StoredScope>(() => readScope(storageKey));
  let current = state;
  if (state.storageKey !== storageKey) {
    current = readScope(storageKey);
    setState(current);
  }
  const latest = useRef(current);
  latest.current = current;
  const unconfirmedKey = current.checked ? '' : current.scope.threats
    .filter((threat) => !current.confirmedIds.has(threat.value))
    .map((threat) => threat.value)
    .join(',');

  useEffect(() => {
    if (!unconfirmedKey) return undefined;
    const unconfirmedIds = unconfirmedKey.split(',');
    // Cancelled when the user changes too: an answer for the previous user is dropped
    let cancelled = false;
    fetchQuery(defenseScopeThreatsQuery, {
      types: DEFENSE_THREAT_TYPES,
      filters: { mode: 'and' as const, filters: [{ key: ['ids'], values: unconfirmedIds }], filterGroups: [] },
      first: unconfirmedIds.length,
    })
      .toPromise()
      .then((data) => {
        if (cancelled) return;
        const edges = (data as useDefenseScopeThreatsQuery$data | undefined)?.stixDomainObjects?.edges ?? [];
        const accessible = new Map<string, DefenseThreatOption>(edges.map(({ node }) => [node.id, { value: node.id, label: node.representative.main, type: node.entity_type }]));
        const previous = latest.current;
        const threats = previous.scope.threats
          .filter((threat) => !unconfirmedIds.includes(threat.value) || accessible.has(threat.value))
          .map((threat) => accessible.get(threat.value) ?? threat);
        const scope = { ...previous.scope, threats };
        setState({ storageKey, scope, confirmedIds: new Set([...previous.confirmedIds, ...accessible.keys()]), checked: true });
        writeStoredScope(storageKey, scope);
      })
      .catch(() => {
        if (!cancelled) setState({ ...latest.current, checked: true });
      });
    return () => {
      cancelled = true;
    };
  }, [storageKey, unconfirmedKey]);

  const updateScope = useCallback((next: DefenseScopeState) => {
    const previous = latest.current;
    // The threats of the next scope come from the scope in use or from the search of the reader. The stored threats
    // not confirmed are hidden from the reader, who cannot have removed them: they stay stored.
    const nextIds = new Set(next.threats.map((threat) => threat.value));
    const hidden = previous.scope.threats.filter((threat) => !previous.confirmedIds.has(threat.value) && !nextIds.has(threat.value));
    const scope = { ...next, threats: [...next.threats, ...hidden].slice(0, DEFENSE_MAX_SELECTED_THREATS) };
    setState({ storageKey, scope, confirmedIds: new Set([...previous.confirmedIds, ...nextIds]), checked: previous.checked });
    writeStoredScope(storageKey, scope);
  }, [storageKey]);

  const scopeInUse = useMemo(
    () => ({ ...current.scope, threats: current.scope.threats.filter((threat) => current.confirmedIds.has(threat.value)) }),
    [current.scope, current.confirmedIds],
  );
  const ready = current.scope.threatMode !== 'SELECTED' || !unconfirmedKey;
  return [scopeInUse, updateScope, ready];
};

export default useDefenseScope;
