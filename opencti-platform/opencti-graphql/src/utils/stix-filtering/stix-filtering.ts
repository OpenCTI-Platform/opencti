//----------------------------------------------------------------------------------------------------------
// TYPES: TODO: remove them from here and use the one defined for #2686

import {
  ASSIGNEE_FILTER,
  CONFIDENCE_FILTER,
  CREATED_BY_FILTER,
  CREATOR_FILTER,
  DETECTION_FILTER,
  INDICATOR_FILTER,
  INSTANCE_FILTER,
  LABEL_FILTER,
  MAIN_OBSERVABLE_TYPE_FILTER,
  MARKING_FILTER,
  OBJECT_CONTAINS_FILTER,
  PATTERN_FILTER,
  RELATION_FROM,
  RELATION_FROM_TYPES,
  RELATION_TO, RELATION_TO_TYPES,
  REVOKED_FILTER,
  SCORE_FILTER,
  TYPE_FILTER,
  WORKFLOW_FILTER
} from '../filtering';

export type FilterMode = 'AND' | 'OR';
export type FilterOperator = 'eq' | 'not_eq' | 'lt' | 'lte' | 'gt' | 'gte' | 'nil' | 'not_nil';

export type Filter = {
  // multiple keys possible (internal use, in streams it's not possible)
  // TODO: it should probably be named keys, but that's another story.
  key: string[] // name, entity_type, etc
  mode: FilterMode
  values: string[]
  operator: FilterOperator
};

export type FilterGroup = {
  mode: FilterMode
  filters: Filter[]
  filterGroups: FilterGroup[]
};
//----------------------------------------------------------------------------------------------------------

/**
 * Resolve some of the values (recursively) inside the filter group
 * so that testers work properly on either the unresolved ids or the resolved values (from the ids)
 * To date, this applies to: Indicators, labels.
 * @param filter
 */
export const adaptFilter = (filter: FilterGroup): FilterGroup => {
  // TODO
  return filter;
};

export const isStixMatchFilter = (stix: any, filter: Filter) : boolean => {
  // Filter format is capable or multi-key but we are only compatible with single-key filtering for now
  switch (filter.key[0]) {
    case MARKING_FILTER:
    case TYPE_FILTER:
    case INSTANCE_FILTER:
    case INDICATOR_FILTER:
    case WORKFLOW_FILTER:
    case CREATED_BY_FILTER:
    case CREATOR_FILTER:
    case ASSIGNEE_FILTER:
    case LABEL_FILTER:
    case REVOKED_FILTER:
    case DETECTION_FILTER:
    case SCORE_FILTER:
    case CONFIDENCE_FILTER:
    case PATTERN_FILTER:
    case MAIN_OBSERVABLE_TYPE_FILTER:
    case OBJECT_CONTAINS_FILTER:
    case RELATION_FROM:
    case RELATION_TO:
    case RELATION_FROM_TYPES:
    case RELATION_TO_TYPES:
    default:
      return false;
  }
};
