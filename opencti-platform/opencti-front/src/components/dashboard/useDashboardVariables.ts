import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../utils/hooks/useAuth';
import useHelper from '../../utils/hooks/useHelper';
import type { DashboardVariable } from './dashboard-types';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from './dashboardVariablesFeatureFlag';
import { buildDefaultVariableValues, isValidVariableValue } from './dashboardVariablesResolution';
import { dashboardVariablesStorageKey, parseVariablesParam, readStoredVariableValues, writeStoredVariableValues, writeVariablesParam } from './dashboardVariablesStorage';

interface UseDashboardVariablesOptions {
  ignoreLocalValues?: boolean;
  // Values that replace the manifest defaults (the preset a group or the user opens this dashboard on): what the
  // user starts from, and what Reset goes back to.
  defaultOverrides?: ReadonlyMap<string, string>;
}

export const useDashboardVariables = (
  workspaceId: string,
  variables: DashboardVariable[],
  { ignoreLocalValues = false, defaultOverrides }: UseDashboardVariablesOptions = {},
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

  // The defaults of the manifest alone: what a preset falls back to for the variables it does not hold, whatever
  // preset the user opens the dashboard on.
  const manifestOnly = buildDefaultVariableValues(enabled ? variables : []);
  const manifestSignature = JSON.stringify([...manifestOnly]);
  const manifestDefaults = useMemo(() => new Map<string, string>(JSON.parse(manifestSignature)), [manifestSignature]);
  const overridden = new Map(manifestOnly);
  if (enabled && defaultOverrides) {
    variables.forEach((variable) => {
      const value = defaultOverrides.get(variable.id);
      if (value !== undefined && value !== '' && isValidVariableValue(variable, value)) overridden.set(variable.id, value);
    });
  }
  const defaultsSignature = JSON.stringify([...overridden]);
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

  // The URL shows the values in use, also when they were restored from this browser: a shared address opens the same
  // view. Only the variables that still exist.
  useEffect(() => {
    if (ignoreLocalValues || !enabled) return;
    const ids = new Set<string>(JSON.parse(idsSignature));
    writeVariablesParam(Object.fromEntries(Object.entries(stored).filter(([id]) => ids.has(id))));
  }, [stored, ignoreLocalValues, enabled, idsSignature]);

  const setValue = useCallback((variableId: string, value: string) => {
    if (ignoreLocalValues || !enabled) return;
    // Based on the in-memory state, not on a re-read of the storage, which may have refused the previous write.
    const { [variableId]: _previous, ...others } = stored;
    // An empty value means "unset": the manifest default applies.
    commit(value === '' ? others : { ...others, [variableId]: value });
  }, [commit, stored, ignoreLocalValues, enabled]);

  // Replaces every local value at once (a preset): a value equal to the default is not kept locally.
  const setValues = useCallback((next: ReadonlyMap<string, string>) => {
    if (ignoreLocalValues || !enabled) return;
    const entries = [...next].filter(([id, value]) => value !== '' && value !== defaults.get(id));
    commit(Object.fromEntries(entries));
  }, [commit, defaults, ignoreLocalValues, enabled]);

  const reset = useCallback(() => {
    if (ignoreLocalValues || !enabled) return;
    commit({});
  }, [commit, ignoreLocalValues, enabled]);

  // `resetValues` is called once an asynchronous action is done: it must read the values as they are then, not as
  // they were when the action started, otherwise it would put back what the user changed in the meantime.
  const latest = useRef({ stored, commit });
  useEffect(() => {
    latest.current = { stored, commit };
  });
  // Drops the stored values that still are the given ones, and keeps any other (a value changed since).
  const resetValues = useCallback((submitted: ReadonlyMap<string, string>) => {
    if (ignoreLocalValues || !enabled) return;
    const { stored: current, commit: commitCurrent } = latest.current;
    commitCurrent(Object.fromEntries(Object.entries(current).filter(([id, value]) => submitted.get(id) !== value)));
  }, [ignoreLocalValues, enabled]);

  return { values, defaults, manifestDefaults, setValue, setValues, reset, resetValues };
};
