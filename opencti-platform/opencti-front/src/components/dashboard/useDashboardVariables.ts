import { useCallback, useMemo, useState } from 'react';
import useAuth from '../../utils/hooks/useAuth';
import useHelper from '../../utils/hooks/useHelper';
import type { DashboardVariable } from './dashboard-types';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from './dashboardVariablesFeatureFlag';
import { buildDefaultVariableValues } from './dashboardVariablesResolution';
import { dashboardVariablesStorageKey, readStoredVariableValues, writeStoredVariableValues } from './dashboardVariablesStorage';

const isInPool = (variable: DashboardVariable, value: string) => (
  variable.restriction.mode !== 'selection' || variable.restriction.values.includes(value)
);

export const useDashboardVariables = (
  workspaceId: string,
  variables: DashboardVariable[],
  { ignoreLocalValues = false }: { ignoreLocalValues?: boolean } = {},
) => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const enabled = isFeatureEnable(DASHBOARD_VARIABLES_FEATURE_FLAG);
  const key = dashboardVariablesStorageKey(me.id, workspaceId);
  const load = () => (ignoreLocalValues || !enabled ? {} : readStoredVariableValues(key));
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
        if (value !== undefined && isInPool(variable, value)) merged.set(variable.id, value);
      });
    }
    return merged;
  }, [defaults, stored, enabled, ignoreLocalValues, variablesSignature]);

  const effectiveSignature = JSON.stringify([...effective]);
  const values = useMemo(() => new Map<string, string>(JSON.parse(effectiveSignature)), [effectiveSignature]);

  const commit = useCallback((next: Record<string, string>) => {
    writeStoredVariableValues(key, next);
    setState({ key, stored: next });
  }, [key]);

  const setValue = useCallback((variableId: string, value: string) => {
    if (ignoreLocalValues) return;
    commit({ ...readStoredVariableValues(key), [variableId]: value });
  }, [commit, key, ignoreLocalValues]);

  const reset = useCallback(() => {
    if (ignoreLocalValues) return;
    commit({});
  }, [commit, ignoreLocalValues]);

  const isModified = [...values].some(([id, value]) => defaults.get(id) !== value);
  return { values, defaults, setValue, reset, isModified };
};
