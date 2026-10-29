import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../utils/hooks/useAuth';
import useHelper from '../../utils/hooks/useHelper';
import type { DashboardConfig } from './dashboard-types';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from './dashboardVariablesFeatureFlag';
import { applyDateChange, isSameTimeRange, pickTimeRange, type DashboardDateField, type DashboardTimeRange } from './dashboardTimeRange';
import { dashboardTimeRangeStorageKey, parseTimeRangeParam, readStoredTimeRange, writeStoredTimeRange, writeTimeRangeParam } from './dashboardTimeRangeStorage';

/**
 * Time range of a dashboard for the current user: the one of the manifest unless the user picked another, which is
 * kept in this browser and in the URL. Changing it never writes the dashboard.
 */
export const useDashboardTimeRange = (
  workspaceId: string,
  config: DashboardConfig,
  { ignoreLocalValues = false }: { ignoreLocalValues?: boolean } = {},
) => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const enabled = isFeatureEnable(DASHBOARD_VARIABLES_FEATURE_FLAG);
  const key = dashboardTimeRangeStorageKey(me.id, workspaceId);
  // Priority: URL > localStorage > manifest (applied below).
  const load = () => (ignoreLocalValues || !enabled ? null : parseTimeRangeParam(window.location.search) ?? readStoredTimeRange(key));
  const [state, setState] = useState(() => ({ key, ignoreLocalValues, enabled, stored: load() }));
  // Same as the variable values: another account or dashboard, or local values that stop being ignored, need a fresh read.
  let { stored } = state;
  if (state.key !== key || state.ignoreLocalValues !== ignoreLocalValues || state.enabled !== enabled) {
    stored = load();
    setState({ key, ignoreLocalValues, enabled, stored });
  }

  const { startDate, endDate, relativeDate } = pickTimeRange(config);
  const defaultRange = useMemo(() => ({ startDate, endDate, relativeDate }), [startDate, endDate, relativeDate]);
  const range = stored ?? defaultRange;
  // Compared with the default, not tested for a local entry: the default may have caught up with it.
  const isModified = !isSameTimeRange(range, defaultRange);

  const commit = useCallback((next: DashboardTimeRange | null) => {
    writeStoredTimeRange(key, next);
    writeTimeRangeParam(next);
    setState({ key, ignoreLocalValues, enabled, stored: next });
  }, [key, ignoreLocalValues, enabled]);

  const setDate = useCallback((type: DashboardDateField, value: string | null) => {
    if (ignoreLocalValues || !enabled) return;
    const next = applyDateChange(range, type, value);
    // Back to the default: nothing to keep.
    commit(isSameTimeRange(next, defaultRange) ? null : next);
  }, [commit, range, defaultRange, ignoreLocalValues, enabled]);

  const reset = useCallback(() => {
    if (ignoreLocalValues || !enabled) return;
    commit(null);
  }, [commit, ignoreLocalValues, enabled]);

  // Called once an asynchronous action is done: reads the range as it is then (see resetValues of the variables).
  const latest = useRef({ stored, commit });
  useEffect(() => {
    latest.current = { stored, commit };
  });
  // Drops the local range if it still is the given one, and keeps it otherwise (changed since).
  const resetRange = useCallback((submitted: DashboardTimeRange) => {
    if (ignoreLocalValues || !enabled) return;
    const { stored: current, commit: commitCurrent } = latest.current;
    if (current && isSameTimeRange(current, submitted)) commitCurrent(null);
  }, [ignoreLocalValues, enabled]);

  return { range, defaultRange, isModified, setDate, reset, resetRange };
};
