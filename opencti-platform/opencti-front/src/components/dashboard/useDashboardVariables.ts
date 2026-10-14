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
  // Priority: URL > localStorage > default (the default is applied below).
  const load = () => (ignoreLocalValues || !enabled ? {} : { ...readStoredVariableValues(key), ...parseVariablesParam(window.location.search) });
  const [state, setState] = useState(() => ({ key, ignoreLocalValues, enabled, stored: load() }));
  // The stored values are tied to what they were read for: another account or dashboard, or local values that
  // stop being ignored (viewer toggle opened, flag resolved late), need a fresh read. Once re-read, the state is stable.
  let { stored } = state;
  if (state.key !== key || state.ignoreLocalValues !== ignoreLocalValues || state.enabled !== enabled) {
    stored = load();
    setState({ key, ignoreLocalValues, enabled, stored });
  }

  const defaultsSignature = JSON.stringify([...buildDefaultVariableValues(enabled ? variables : [])]);
  const defaults = useMemo(() => new Map<string, string>(JSON.parse(defaultsSignature)), [defaultsSignature]);

  // `variables` is deliberately summarized by its signature (id + selection pool).
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
    setState({ key, ignoreLocalValues, enabled, stored: kept });
  }, [key, ignoreLocalValues, enabled, idsSignature]);

  const setValue = useCallback((variableId: string, value: string) => {
    if (ignoreLocalValues || !enabled) return;
    // Based on the in-memory state, not on a re-read of the storage, which may have refused the previous write.
    const { [variableId]: _previous, ...others } = stored;
    // An empty value means "unset": the manifest default applies.
    commit(value === '' ? others : { ...others, [variableId]: value });
  }, [commit, stored, ignoreLocalValues, enabled]);

  const reset = useCallback(() => {
    if (ignoreLocalValues || !enabled) return;
    commit({});
  }, [commit, ignoreLocalValues, enabled]);

  return { values, defaults, setValue, reset };
};
