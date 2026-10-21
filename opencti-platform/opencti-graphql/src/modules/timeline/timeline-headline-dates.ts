import type { AuthContext } from '../../types/user';
import type { FilterDefinition } from '../../domain/filterKeysSchema';
import { getEntitySettingFromCache } from '../entitySetting/entitySetting-utils';
import { resolveTimelineHeadlineDates } from './timeline-anchors';
import { ATTRIBUTE_TIMELINE_ANCHORS, isTimelineContainerType, TIMELINE_ANCHOR_KEYS, TIMELINE_CONTAINER_TYPES, type TimelineAnchorKey } from './timeline-types';

/** Headline dates of the timelines of a type, as its customization (Settings > Customization) sets them. */
export const loadTimelineHeadlineDates = async (context: AuthContext, entityType: string): Promise<TimelineAnchorKey[]> => {
  const entitySetting = await getEntitySettingFromCache(context, entityType);
  return resolveTimelineHeadlineDates(entitySetting?.timeline_headline_dates);
};

/**
 * The anchor filters follow the headline dates of each timeline type: a filter key names only the types that show its
 * date, and a date no type of the list shows is left out. Stored filters on it still apply.
 */
export const restrictTimelineAnchorFilterKeys = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  headlineDatesByType: Record<string, readonly TimelineAnchorKey[]>,
) => {
  filterKeysSchema.forEach((definitions) => {
    TIMELINE_ANCHOR_KEYS.forEach((key) => {
      const filterKey = `${ATTRIBUTE_TIMELINE_ANCHORS}.${key}`;
      const definition = definitions.get(filterKey);
      if (!definition) return;
      const subEntityTypes = definition.subEntityTypes.filter((type) => !isTimelineContainerType(type) || (headlineDatesByType[type] ?? []).includes(key));
      if (subEntityTypes.some(isTimelineContainerType)) {
        definitions.set(filterKey, { ...definition, subEntityTypes });
      } else {
        definitions.delete(filterKey);
      }
    });
  });
};

export const loadTimelineHeadlineDatesByType = async (context: AuthContext): Promise<Record<string, TimelineAnchorKey[]>> => {
  const entries = await Promise.all(TIMELINE_CONTAINER_TYPES.map(async (type) => [type, await loadTimelineHeadlineDates(context, type)] as const));
  return Object.fromEntries(entries);
};
