import { useCallback, useMemo, useState } from 'react';
import useAuth from '../../utils/hooks/useAuth';
import useHelper from '../../utils/hooks/useHelper';
import type { DashboardVariable } from './dashboard-types';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from './dashboardVariablesFeatureFlag';
import { buildDefaultVariableValues, isValidVariableValue } from './dashboardVariablesResolution';
import { dashboardVariablesStorageKey, parseVariablesParam, readStoredVariableValues, writeStoredVariableValues, writeVariablesParam } from './dashboardVariablesStorage';

export const useDashboardVariables = (
  workspaceId: string,
  variables: DashboardVariable[],
  { ignoreLocalValues = false }: { ignoreLocalValues?: boolean } = {},
) => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const enabled = isFeatureEnable(DASHBOARD_VARIABLES_FEATURE_FLAG);
  const key = dashboardVariablesStorageKey(me.id, workspaceId);
  // Priorité : URL > localStorage > défaut (le défaut est appliqué plus bas).
  const load = () => (ignoreLocalValues || !enabled ? {} : { ...readStoredVariableValues(key), ...parseVariablesParam(window.location.search) });
  const [state, setState] = useState(() => ({ key, stored: load() }));
  // Changement de compte ou de dashboard : on relit, on ne garde jamais l'état d'une autre clé.
  const stored = state.key === key ? state.stored : load();

  const defaultsSignature = JSON.stringify([...buildDefaultVariableValues(enabled ? variables : [])]);
  const defaults = useMemo(() => new Map<string, string>(JSON.parse(defaultsSignature)), [defaultsSignature]);

  // `variables` est volontairement résumé par sa signature (id + pool de sélection).
  const variablesSignature = JSON.stringify(variables.map((v) => [v.id, v.restriction.mode === 'selection' ? v.restriction.values : null]));
  const effective = useMemo(() => {
    const merged = new Map(defaults);
    if (enabled && !ignoreLocalValues) {
      variables.forEach((variable) => {
        const value = stored[variable.id];
        if (value !== undefined && isValidVariableValue(variable, value)) merged.set(variable.id, value);
      });
    }
    return merged;
  }, [defaults, stored, enabled, ignoreLocalValues, variablesSignature]);

  const effectiveSignature = JSON.stringify([...effective]);
  const values = useMemo(() => new Map<string, string>(JSON.parse(effectiveSignature)), [effectiveSignature]);

  // Only the variables that still exist are persisted: the entry of a deleted one is dropped at the next write.
  const idsSignature = JSON.stringify(variables.map((v) => v.id));
  const commit = useCallback((next: Record<string, string>) => {
    const ids = new Set<string>(JSON.parse(idsSignature));
    const kept = Object.fromEntries(Object.entries(next).filter(([id]) => ids.has(id)));
    writeStoredVariableValues(key, kept);
    writeVariablesParam(kept);
    setState({ key, stored: kept });
  }, [key, idsSignature]);

  const setValue = useCallback((variableId: string, value: string) => {
    if (ignoreLocalValues || !enabled) return;
    // Based on the in-memory state, not on a re-read of the storage, which may have refused the previous write.
    const { [variableId]: _previous, ...others } = stored;
    // Une valeur vide signifie « non définie » : le défaut du manifest s'applique.
    commit(value === '' ? others : { ...others, [variableId]: value });
  }, [commit, stored, ignoreLocalValues, enabled]);

  const reset = useCallback(() => {
    if (ignoreLocalValues || !enabled) return;
    commit({});
  }, [commit, ignoreLocalValues, enabled]);

  return { values, defaults, setValue, reset };
};
