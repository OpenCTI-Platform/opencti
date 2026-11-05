import { useCallback, useEffect, useMemo, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import type { DashboardPreset } from '../dashboard-types';
import { dashboardPresetStorageKey, parsePresetParam, readStoredPresetId, writePresetParam, writeStoredPresetId } from './dashboardPresetStorage';

interface UseDashboardPresetOptions {
  // The home dashboard and a user without the selector only ever see the default preset: nothing local is read or written.
  ignoreLocalValues?: boolean;
  enabled?: boolean;
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
  { ignoreLocalValues = false, enabled = true, defaultPresetId = null }: UseDashboardPresetOptions = {},
) => {
  const { me } = useAuth();
  const key = dashboardPresetStorageKey(me.id, workspaceId);
  const load = () => (ignoreLocalValues || !enabled ? null : parsePresetParam(window.location.search) ?? readStoredPresetId(key));
  const [state, setState] = useState(() => ({ key, ignoreLocalValues, enabled, stored: load() }));
  let { stored } = state;
  if (state.key !== key || state.ignoreLocalValues !== ignoreLocalValues || state.enabled !== enabled) {
    stored = load();
    setState({ key, ignoreLocalValues, enabled, stored });
  }

  const presetIds = presets.map((preset) => preset.id).join();
  const effectiveDefaultId = enabled && defaultPresetId && presets.some((preset) => preset.id === defaultPresetId) ? defaultPresetId : null;
  // A stored preset that was deleted meanwhile falls back to the default one.
  const activeId = stored && presets.some((preset) => preset.id === stored) ? stored : effectiveDefaultId;
  const activePreset = useMemo(
    () => (activeId ? presets.find((preset) => preset.id === activeId) ?? null : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [activeId, presetIds, presets],
  );
  const defaultPreset = useMemo(
    () => (effectiveDefaultId ? presets.find((preset) => preset.id === effectiveDefaultId) ?? null : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [effectiveDefaultId, presetIds, presets],
  );

  // The URL shows the preset in use, also when it was restored from this browser: a shared address opens the same view.
  useEffect(() => {
    if (!ignoreLocalValues && enabled) writePresetParam(stored && presets.some((preset) => preset.id === stored) ? stored : null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stored, ignoreLocalValues, enabled, presetIds]);

  const commit = useCallback((next: string | null) => {
    writeStoredPresetId(key, next);
    writePresetParam(next);
    setState({ key, ignoreLocalValues, enabled, stored: next });
  }, [key, ignoreLocalValues, enabled]);

  // Selects a preset for this user (null: back to the default preset, or none).
  const select = useCallback((presetId: string | null) => {
    if (ignoreLocalValues || !enabled) return;
    commit(presetId === effectiveDefaultId ? null : presetId);
  }, [commit, ignoreLocalValues, enabled, effectiveDefaultId]);

  return { activePreset, defaultPreset, select };
};
