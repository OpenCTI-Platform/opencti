//----------------------------------------------------------------------------------------------------------
// TYPES: TODO: remove them from here and use the one defined for #2686

import {
  // ASSIGNEE_FILTER,
  CONFIDENCE_FILTER,
  CREATED_BY_FILTER,
  // CREATOR_FILTER,
  DETECTION_FILTER,
  INDICATOR_FILTER,
  INSTANCE_FILTER,
  // LABEL_FILTER,
  MAIN_OBSERVABLE_TYPE_FILTER,
  // MARKING_FILTER,
  // OBJECT_CONTAINS_FILTER,
  PATTERN_FILTER,
  RELATION_FROM,
  RELATION_FROM_TYPES,
  RELATION_TO, RELATION_TO_TYPES,
  REVOKED_FILTER,
  SCORE_FILTER,
  TYPE_FILTER,
  WORKFLOW_FILTER
} from '../filtering';
import { logApp } from '../../config/conf';
import {
  testAssignee,
  testConfidence,
  testCreatedBy,
  testCreator,
  testDetection,
  testEntityType,
  testIndicator,
  testInstanceType,
  testLabel,
  testMainObservableType,
  testMarkingFilter,
  testObjectContains,
  testPattern,
  testRelationFrom,
  testRelationFromTypes,
  testRelationTo, testRelationToTypes,
  testRevoked,
  testScore,
  testWorkflow
} from './stix-testers';

// TODO: changed by Cathia, to integrate properly with her
// not used: participant > objectParticipant | killChainPhase > killChainPhases
const ASSIGNEE_FILTER = 'objectAssignee';
const CREATOR_FILTER = 'creator_id';
const LABEL_FILTER = 'objectLabel';
const MARKING_FILTER = 'objectMarking';
const OBJECT_CONTAINS_FILTER = 'objects';

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
 * To date, we need to use the resolved values instead of ids for: Indicators, labels.
 * @param filter
 */
export const adaptFilter = (filter: Filter): Filter => {
  if (filter.key[0] === INDICATOR_FILTER || filter.key[0] === LABEL_FILTER) {
    return {
      ...filter,
      values: filter.values.map((id) => id) // TODO: resolve into values
    };
  }
  return filter;
};

export const adaptFilterGroup = (filterGroup: FilterGroup): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => adaptFilter(f)),
    filterGroups: filterGroup.filterGroups.map((fg) => adaptFilterGroup(fg))
  };
};

export const isStixMatchFilter = (stix: any, filter: Filter, useSideEventMatching = false) : boolean => {
  // Filter format is capable or multi-key but we are only compatible with single-key filtering for now
  if (filter.key.length > 1) {
    logApp.warn(`[OPENCTI] multiple keys found in filter: [${JSON.stringify(filter.key)}] - only first key is used.`);
  }

  switch (filter.key[0]) {
    case MARKING_FILTER:
      return testMarkingFilter(stix, filter);
    case TYPE_FILTER:
      return testEntityType(stix, filter);
    case INSTANCE_FILTER:
      return testInstanceType(stix, filter, useSideEventMatching);
    case INDICATOR_FILTER:
      return testIndicator(stix, filter);
    case WORKFLOW_FILTER:
      return testWorkflow(stix, filter);
    case CREATED_BY_FILTER:
      return testCreatedBy(stix, filter);
    case CREATOR_FILTER:
      return testCreator(stix, filter);
    case ASSIGNEE_FILTER:
      return testAssignee(stix, filter);
    case LABEL_FILTER:
      return testLabel(stix, filter);
    case REVOKED_FILTER:
      return testRevoked(stix, filter);
    case DETECTION_FILTER:
      return testDetection(stix, filter);
    case SCORE_FILTER:
      return testScore(stix, filter);
    case CONFIDENCE_FILTER:
      return testConfidence(stix, filter);
    case PATTERN_FILTER:
      return testPattern(stix, filter);
    case MAIN_OBSERVABLE_TYPE_FILTER:
      return testMainObservableType(stix, filter);
    case OBJECT_CONTAINS_FILTER:
      return testObjectContains(stix, filter);
    case RELATION_FROM:
      return testRelationFrom(stix, filter);
    case RELATION_TO:
      return testRelationTo(stix, filter);
    case RELATION_FROM_TYPES:
      return testRelationFromTypes(stix, filter);
    case RELATION_TO_TYPES:
      return testRelationToTypes(stix, filter);
    default:
      return false;
  }
};

export const isStixMatchFilterGroup = (stix: any, filterGroup: FilterGroup) : boolean => {
  if (filterGroup.mode === 'AND') {
    const results: boolean[] = [];
    if (filterGroup.filters.length > 0) {
      results.push(filterGroup.filters.every((filter) => isStixMatchFilter(stix, filter)));
    }
    if (filterGroup.filterGroups.length > 0) {
      results.push(filterGroup.filterGroups.every((fg) => isStixMatchFilterGroup(stix, fg)));
    }
    return results.length > 0 && results.every((isTrue) => isTrue);
  }

  if (filterGroup.mode === 'OR') {
    if (filterGroup.filters.length > 0) {
      return filterGroup.filters.some((filter) => isStixMatchFilter(stix, filter));
    }
    if (filterGroup.filterGroups.length > 0) {
      return filterGroup.filterGroups.some((fg) => isStixMatchFilterGroup(stix, fg));
    }
  }

  return false;
};
