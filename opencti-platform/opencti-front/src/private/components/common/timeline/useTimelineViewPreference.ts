import { useCallback, useState } from 'react';
import { parseTimelineViewPreference, type TimelineViewPreference } from './timelineUtils';

export const timelineViewPreferenceKey = (containerId: string) => `timeline-view-${containerId}`;

/** Zoom window, grouping and view the reader last chose on the timeline of a container, read without writing anything. */
export const readTimelineViewPreference = (containerId: string): TimelineViewPreference => {
  try {
    return parseTimelineViewPreference(JSON.parse(window.localStorage.getItem(timelineViewPreferenceKey(containerId)) ?? 'null'));
  } catch {
    return {};
  }
};

/**
 * Zoom window, grouping and view of the timeline of a container, kept for the reader in their browser like the views
 * of the lists, so that the timeline opens again as they left it.
 */
const useTimelineViewPreference = (containerId: string): [TimelineViewPreference, (patch: TimelineViewPreference) => void] => {
  const [saved, setSaved] = useState(() => ({ containerId, preference: readTimelineViewPreference(containerId) }));
  let { preference } = saved;
  if (saved.containerId !== containerId) {
    preference = readTimelineViewPreference(containerId);
    setSaved({ containerId, preference });
  }
  const save = useCallback((patch: TimelineViewPreference) => {
    const current = readTimelineViewPreference(containerId);
    const next = { ...current, ...parseTimelineViewPreference(patch) };
    if (next.view === current.view && next.grouping === current.grouping && next.zoom === current.zoom) return;
    try {
      window.localStorage.setItem(timelineViewPreferenceKey(containerId), JSON.stringify(next));
    } catch {
      // Storage full or disabled: the choice still applies to this visit through the address
    }
    setSaved({ containerId, preference: next });
  }, [containerId]);
  return [preference, save];
};

export default useTimelineViewPreference;
