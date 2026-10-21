import { useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import useTimelineViewPreference from './useTimelineViewPreference';
import {
  parseTimelineViewState,
  serializeTimelineViewState,
  TIMELINE_ADD_MILESTONE_PARAM,
  TIMELINE_OPEN_SETTINGS_PARAM,
  TIMELINE_VIEW_DEFAULTS,
  type TimelineViewPreference,
  type TimelineViewState,
} from './timelineUtils';

const REMEMBERED_KEYS = ['view', 'grouping', 'zoom'] as const;

/**
 * View state of the Timeline tab, kept in the address. The zoom window, the grouping and the view the reader picks are
 * also saved for their next visit; the address wins over them, so that a shared link opens as it was sent.
 */
const useTimelineViewState = (containerId: string) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [preference, savePreference] = useTimelineViewPreference(containerId);
  const defaults = useMemo(() => ({ ...TIMELINE_VIEW_DEFAULTS, ...preference }), [preference]);
  const state = useMemo(() => parseTimelineViewState(searchParams, defaults), [searchParams, defaults]);

  // Patches apply to the URL as it is when they land: a delayed domain update never reverts a later change (view, filters).
  // The address names what differs from the first-visit view, whatever the reader saved, so that it reads the same for anyone.
  const updateState = useCallback((patch: Partial<TimelineViewState>) => {
    setSearchParams((current) => serializeTimelineViewState({ ...parseTimelineViewState(current, defaults), ...patch }, TIMELINE_VIEW_DEFAULTS), { replace: true });
    const chosen: TimelineViewPreference = {};
    if (patch.view) chosen.view = patch.view;
    if (patch.grouping) chosen.grouping = patch.grouping;
    if (patch.zoom) chosen.zoom = patch.zoom;
    if (Object.keys(chosen).length > 0) savePreference(chosen);
  }, [defaults, savePreference, setSearchParams]);

  useEffect(() => {
    // Once on opening: the saved choices go to the address so that a link copied right away shows the same view, and the
    // form or the panel asked for by the overview card is not opened again on a reload
    const named = serializeTimelineViewState(state, TIMELINE_VIEW_DEFAULTS);
    const missing = REMEMBERED_KEYS.filter((key) => named.has(key) && !searchParams.has(key));
    if (missing.length === 0 && !searchParams.has(TIMELINE_ADD_MILESTONE_PARAM) && !searchParams.has(TIMELINE_OPEN_SETTINGS_PARAM)) return;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete(TIMELINE_ADD_MILESTONE_PARAM);
      next.delete(TIMELINE_OPEN_SETTINGS_PARAM);
      missing.forEach((key) => next.set(key, named.get(key) as string));
      return next;
    }, { replace: true });
  }, []);

  return { searchParams, state, updateState };
};

export default useTimelineViewState;
