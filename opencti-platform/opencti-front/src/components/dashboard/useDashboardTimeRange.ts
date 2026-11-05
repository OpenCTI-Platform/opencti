import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../utils/hooks/useAuth';
import type { DashboardConfig } from './dashboard-types';
import { applyDateChange, isSameTimeRange, pickTimeRange, type DashboardDateField, type DashboardTimeRange } from './dashboardTimeRange';
import { dashboardTimeRangeStorageKey, parseTimeRangeParam, readStoredTimeRange, writeStoredTimeRange, writeTimeRangeParam } from './dashboardTimeRangeStorage';

/**
 * Time range of a dashboard for the current user: the one of the manifest unless the user picked another, which is
 * kept in this browser and in the URL. Changing it never writes the dashboard.
 */
interface UseDashboardTimeRangeOptions {
  ignoreLocalValues?: boolean;
  // A range that replaces the manifest one as the default (the preset a group or the user opens this dashboard on).
  defaultOverride?: DashboardTimeRange | null;
}

export const useDashboardTimeRange = (
  workspaceId: string,
  config: DashboardConfig,
  { ignoreLocalValues = false, defaultOverride = null }: UseDashboardTimeRangeOptions = {},
) => {
  const { me } = useAuth();
  const key = dashboardTimeRangeStorageKey(me.id, workspaceId);
  // Priority: URL > localStorage > manifest (applied below).
  const load = () => (ignoreLocalValues ? null : parseTimeRangeParam(window.location.search) ?? readStoredTimeRange(key));
  const [state, setState] = useState(() => ({ key, ignoreLocalValues, stored: load() }));
  // Same as the variable values: another account or dashboard, or local values that stop being ignored, need a fresh read.
  let { stored } = state;
  if (state.key !== key || state.ignoreLocalValues !== ignoreLocalValues) {
    stored = load();
    setState({ key, ignoreLocalValues, stored });
  }

  // The URL shows the range in use, also when it was restored from this browser: a shared address opens the same view.
  useEffect(() => {
    if (!ignoreLocalValues) writeTimeRangeParam(stored);
  }, [stored, ignoreLocalValues]);

  const { startDate, endDate, relativeDate } = defaultOverride ?? pickTimeRange(config);
  const defaultRange = useMemo(() => ({ startDate, endDate, relativeDate }), [startDate, endDate, relativeDate]);
  const range = stored ?? defaultRange;
  // Compared with the default, not tested for a local entry: the default may have caught up with it.
  const isModified = !isSameTimeRange(range, defaultRange);

  const commit = useCallback((next: DashboardTimeRange | null) => {
    writeStoredTimeRange(key, next);
    writeTimeRangeParam(next);
    setState({ key, ignoreLocalValues, stored: next });
  }, [key, ignoreLocalValues]);

  const setDate = useCallback((type: DashboardDateField, value: string | null) => {
    if (ignoreLocalValues) return;
    const next = applyDateChange(range, type, value);
    // Back to the default: nothing to keep.
    commit(isSameTimeRange(next, defaultRange) ? null : next);
  }, [commit, range, defaultRange, ignoreLocalValues]);

  // Replaces the whole range at once (a preset): back to the default, nothing is kept.
  const setRange = useCallback((next: DashboardTimeRange) => {
    if (ignoreLocalValues) return;
    commit(isSameTimeRange(next, defaultRange) ? null : next);
  }, [commit, defaultRange, ignoreLocalValues]);

  const reset = useCallback(() => {
    if (ignoreLocalValues) return;
    commit(null);
  }, [commit, ignoreLocalValues]);

  // Called once an asynchronous action is done: reads the range as it is then (see resetValues of the variables).
  const latest = useRef({ stored, commit });
  useEffect(() => {
    latest.current = { stored, commit };
  });
  // Drops the local range if it still is the given one, and keeps it otherwise (changed since).
  const resetRange = useCallback((submitted: DashboardTimeRange) => {
    if (ignoreLocalValues) return;
    const { stored: current, commit: commitCurrent } = latest.current;
    if (current && isSameTimeRange(current, submitted)) commitCurrent(null);
  }, [ignoreLocalValues]);

  return { range, defaultRange, isModified, setDate, setRange, reset, resetRange };
};
