import { useMemo } from 'react';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { resolveTimelineHeadlineDates, type TimelineAnchorKey } from './timelineUtils';

/** Headline dates of the timelines of a type, as Settings > Customization > the type > Timeline sets them. */
const useTimelineHeadlineDates = (entityType: string | null | undefined): TimelineAnchorKey[] => {
  const stored = useEntitySettings(entityType ?? []).find((setting) => setting.target_type === entityType)?.timeline_headline_dates;
  const storedKey = (stored ?? []).join(',');
  return useMemo(() => resolveTimelineHeadlineDates(storedKey ? storedKey.split(',') : []), [storedKey]);
};

export default useTimelineHeadlineDates;
