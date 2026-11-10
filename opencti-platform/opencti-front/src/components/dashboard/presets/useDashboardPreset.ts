import { useCallback, useEffect, useMemo, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import type { DashboardPreset } from '../dashboard-types';
import { dashboardPresetStorageKey, parsePresetParam, readStoredPresetId, writePresetParam, writeStoredPresetId } from './dashboardPresetStorage';
import { dashboardVariablesStorageKey, writeStoredVariableValues } from '../dashboardVariablesStorage';
import { dashboardTimeRangeStorageKey, writeStoredTimeRange } from '../dashboardTimeRangeStorage';

interface UseDashboardPresetOptions {
  // The home dashboard and a user without the selector only ever see the default preset: nothing local is read or written.
  ignoreLocalValues?: boolean;
  // The preset this dashboard opens on for the current user (their own choice, or the one of their group).
  defaultPresetId?: string | null;
}

/**
 * The preset selected by the current user on a dashboard: the one of the URL, else the one kept in this browser,
 * else the default preset of the user (own choice, group or organization), else none. Kept per user and dashboard.
 * A preset that no longer exists is ignored.
 */
export const useDashboardPreset = (
  workspaceId: string,
  presets: readonly DashboardPreset[],
  { ignoreLocalValues = false, defaultPresetId = null }: UseDashboardPresetOptions = {},
) => {
  const { me } = useAuth();
  const key = dashboardPresetStorageKey(me.id, workspaceId);
  const load = () => {
    if (ignoreLocalValues) return null;
    const fromUrl = parsePresetParam(window.location.search);
    const stored = readStoredPresetId(key);
    // A shared address opens the view of its preset: the values and range this user had kept on another preset are
    // dropped, the ones of the address (variables=, timeRange=) still apply as the hooks read them after this one.
    // Only for a preset the dashboard holds: a deleted or mistyped one, or one not loaded yet, drops nothing.
    if (fromUrl && fromUrl !== stored && presets.some((preset) => preset.id === fromUrl)) {
      writeStoredVariableValues(dashboardVariablesStorageKey(me.id, workspaceId), {});
      writeStoredTimeRange(dashboardTimeRangeStorageKey(me.id, workspaceId), null);
    }
    // The preset of the address is kept even when unknown: it applies once the presets of the dashboard hold it.
    return fromUrl ?? stored;
  };
  const [state, setState] = useState(() => ({ key, ignoreLocalValues, stored: load() }));
  let { stored } = state;
  if (state.key !== key || state.ignoreLocalValues !== ignoreLocalValues) {
    stored = load();
    setState({ key, ignoreLocalValues, stored });
  }

  const presetIds = presets.map((preset) => preset.id).join();
  const effectiveDefaultId = defaultPresetId && presets.some((preset) => preset.id === defaultPresetId) ? defaultPresetId : null;
  // A stored preset that was deleted meanwhile falls back to the default one.
  const activeId = stored && presets.some((preset) => preset.id === stored) ? stored : effectiveDefaultId;
  const activePreset = useMemo(
    () => (activeId ? presets.find((preset) => preset.id === activeId) ?? null : null),
    [activeId, presetIds, presets],
  );
  const defaultPreset = useMemo(
    () => (effectiveDefaultId ? presets.find((preset) => preset.id === effectiveDefaultId) ?? null : null),
    [effectiveDefaultId, presetIds, presets],
  );

  // The URL shows the preset in use, also when it was restored from this browser: a shared address opens the same view.
  useEffect(() => {
    if (!ignoreLocalValues) writePresetParam(stored && presets.some((preset) => preset.id === stored) ? stored : null);
  }, [stored, ignoreLocalValues, presetIds]);

  const commit = useCallback((next: string | null) => {
    writeStoredPresetId(key, next);
    writePresetParam(next);
    setState({ key, ignoreLocalValues, stored: next });
  }, [key, ignoreLocalValues]);

  // Selects a preset for this user (null: back to the default preset, or none).
  const select = useCallback((presetId: string | null) => {
    if (ignoreLocalValues) return;
    commit(presetId === effectiveDefaultId ? null : presetId);
  }, [commit, ignoreLocalValues, effectiveDefaultId]);

  return { activePreset, defaultPreset, select };
};
