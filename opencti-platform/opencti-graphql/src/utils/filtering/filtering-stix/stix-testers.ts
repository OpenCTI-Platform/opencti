import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-extensions';
import { generateInternalType, getParentTypes } from '../../../schema/schemaUtils';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../schema/general';
import { stixRefsExtractor } from '../../../schema/stixEmbeddedRelationship';
import { testStringFilter, testNumericFilter, toValidArray, testBooleanFilter } from '../boolean-logic-engine';
import type { TesterFunction } from '../boolean-logic-engine';

import {
  ASSIGNEE_FILTER,
  CONFIDENCE_FILTER,
  CONNECTED_TO_INSTANCE_FILTER,
  CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER,
  CREATED_BY_FILTER,
  CREATOR_FILTER,
  DETECTION_FILTER,
  INDICATOR_FILTER,
  LABEL_FILTER,
  MAIN_OBSERVABLE_TYPE_FILTER,
  MARKING_FILTER,
  OBJECT_CONTAINS_FILTER,
  PATTERN_FILTER,
  PRIORITY_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_TYPES_FILTER,
  REVOKED_FILTER,
  SCORE_FILTER,
  SEVERITY_FILTER,
  TYPE_FILTER,
  WORKFLOW_FILTER
} from '../filtering-constants';
import type { Filter } from '../../../generated/graphql';

//-----------------------------------------------------------------------------------
// Testers for each possible filter.
// The stix object format is sometimes very different from what we store internally
// and in our filters, so we need extra, specific steps.
// TODO: we use the type any for the stix object; we lack proper types to address this very complex model

/**
 * MARKINGS
 * - objectMarking is object_marking_refs in stix
 */
export const testMarkingFilter = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.object_marking_refs ?? [];
  return testStringFilter(filter, stixValues);
};

/**
 * ENTITY TYPES
 * - entity_type is type in stix (in extension or generated from stix data)
 * - we must also search in parent types
 */
export const testEntityType = (stix: any, filter: Filter) => {
  const stixValue: string = stix.extensions?.[STIX_EXT_OCTI]?.type ?? generateInternalType(stix);
  const extendedStixValues = [stixValue, ...getParentTypes(stixValue)];
  return testStringFilter(filter, extendedStixValues);
};

/**
 * INDICATORS
 * - search must be insensitive to case due to constraint in frontend keywords (using "runtimeAttribute" based on keyword which is always lowercase)
 */
export const testIndicatorTypes = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.indicator_types ?? [];
  return testStringFilter(filter, stixValues);
};

/**
 * WORKFLOWS
 * - x_opencti_workflow_id is workflow_id in stix (in extension)
 */
export const testWorkflow = (stix: any, filter: Filter) => {
  const stixValue: string | null = stix.extensions?.[STIX_EXT_OCTI].workflow_id;
  return testStringFilter(filter, toValidArray(stixValue));
};

/**
 * CREATED BY
 * - createdBy is created_by_ref in stix (in first level or in extension)
 */
export const testCreatedBy = (stix: any, filter: Filter) => {
  const stixValues: string[] = [...toValidArray(stix.created_by_ref), ...toValidArray(stix.extensions?.[STIX_EXT_OCTI_SCO]?.created_by_ref)];
  return testStringFilter(filter, stixValues);
};

/**
 * TECHNICAL CREATORS
 * - creator is creator_ids in stix (in extension)
 */
export const testCreator = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI]?.creator_ids ?? [];
  return testStringFilter(filter, stixValues);
};

/**
 * ASSIGNEES
 * - assigneeTo is assignee_ids in stix (in extension)
 */
export const testAssignee = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI]?.assignee_ids ?? [];
  return testStringFilter(filter, stixValues);
};

/**
 * LABELS
 * - "no-label" is defined by using the operator nil (no longer a "fake" value with id=null)
 * - labelledBy is labels in stix (in first level or in extension)
 */
export const testLabel = (stix: any, filter: Filter) => {
  const stixValues: string[] = [...(stix.labels ?? []), ...(stix.extensions?.[STIX_EXT_OCTI_SCO]?.labels ?? [])];
  return testStringFilter(filter, stixValues);
};

/**
 * REVOKED
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testRevoked = (stix: any, filter: Filter) => {
  const stixValue: boolean | undefined = stix.revoked;
  return testBooleanFilter(filter, stixValue);
};

/**
 * DETECTION
 * - x_opencti_detection is detection in stix extension
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testDetection = (stix: any, filter: Filter) => {
  const stixValue: boolean | undefined = stix.extensions?.[STIX_EXT_OCTI]?.detection;
  return testBooleanFilter(filter, stixValue);
};

/**
 * SCORE
 * - x_opencti_score is x_opencti_score or score in stix (first level or extensions)
 * - numerical value stored in id that must be parsed from string
 */
export const testScore = (stix: any, filter: Filter) => {
  // path depends on entity type
  // do not take all possible scores in stix, we implement a priority order
  const stixValue: number | null = stix.x_opencti_score ?? stix.extensions?.[STIX_EXT_OCTI]?.score ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.score ?? null;
  return testNumericFilter(filter, stixValue);
};

/**
 * CONFIDENCE
 * - numerical value stored in id that must be parsed from string
 */
export const testConfidence = (stix: any, filter: Filter) => {
  const stixValue: number | null = stix.confidence ?? null;
  return testNumericFilter(filter, stixValue);
};

/**
 * PATTERN
 */
export const testPattern = (stix: any, filter: Filter) => {
  const stixValues: string[] = toValidArray(stix.pattern_type);
  return testStringFilter(filter, stixValues);
};

/**
 * MAIN OBSERVABLE TYPES
 * - x_opencti_main_observable_type is main_observable_type in stix extension
 */
export const testMainObservableType = (stix: any, filter: Filter) => {
  const stixValues: string[] = toValidArray(stix.extensions?.[STIX_EXT_OCTI]?.main_observable_type);
  return testStringFilter(filter, stixValues);
};

/**
 * OBJECT CONTAINS
 * - objectContains is object_refs+object_refs_inferred in stix (first level and extension)
 */
export const testObjectContains = (stix: any, filter: Filter) => {
  const stixValues: string[] = [...(stix.object_refs ?? []), ...(stix.extensions?.[STIX_EXT_OCTI]?.object_refs_inferred ?? [])];
  return testStringFilter(filter, stixValues);
};

/**
 * SEVERITY
 */
export const testSeverity = (stix: any, filter: Filter) => {
  const stixValues: string[] = toValidArray(stix.severity);
  return testStringFilter(filter, stixValues);
};

/**
 * PRIORITY
 */
export const testPriority = (stix: any, filter: Filter) => {
  const stixValues: string[] = toValidArray(stix.priority);
  return testStringFilter(filter, stixValues);
};

/**
 * RELATION FROM
 * - depending on stix type (relation or sighting), we might search in source_ref or sighting_of_ref
 */
export const testRelationFrom = (stix: any, filter: Filter) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const stixValues: string[] = toValidArray(stix.source_ref);
    return testStringFilter(filter, stixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = toValidArray(stix.sighting_of_ref);
    return testStringFilter(filter, stixValues);
  }
  return false;
};

/**
 * RELATION FROM
 * - depending on stix type (relation or sighting), we might search in target_ref or where_sighted_refs (plurals!)
 */
export const testRelationTo = (stix: any, filter: Filter) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const stixValues: string[] = toValidArray(stix.target_ref);
    return testStringFilter(filter, stixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = stix.where_sighted_refs ?? [];
    return testStringFilter(filter, stixValues);
  }
  return false;
};

/**
 * RELATION FROM TYPES
 * - depending on stix type (relation or sighting), we might search in source_type or sighting_of_type (in extension)
 * - we must also search in parent types
 */
export const testRelationFromTypes = (stix: any, filter: Filter) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const stixValue = stix.extensions?.[STIX_EXT_OCTI].source_type ?? [];
    const extendedStixValues: string[] = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
    return testStringFilter(filter, extendedStixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValue = stix.extensions?.[STIX_EXT_OCTI].sighting_of_type ?? [];
    const extendedStixValues: string[] = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
    return testStringFilter(filter, extendedStixValues);
  }
  return false;
};

/**
 * RELATION TO TYPES
 * - depending on stix type (relation or sighting), we might search in target_type or where_sighted_types (in extension)
 * - we must also search in parent types
 */
export const testRelationToTypes = (stix: any, filter: Filter) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const stixValue: string = stix.extensions?.[STIX_EXT_OCTI].target_type ?? [];
    const extendedStixValues: string[] = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
    return testStringFilter(filter, extendedStixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI].where_sighted_types ?? [];
    const extendedStixValues = [...stixValues, ...stixValues.map((t) => getParentTypes(t)).flat()];
    return testStringFilter(filter, extendedStixValues);
  }
  return false;
};

/**
 * CONNECTED TO for DIRECT EVENTS ONLY
 * test if the stix is directly related to the instance id
 */
export const testConnectedTo = (stix: any, filter: Filter) => {
  // only applies with "eq" operator
  if (filter.operator && filter.operator !== 'eq') {
    return false;
  }
  return testStringFilter(filter, [stix.id]);
};

/**
 * CONNECTED TO for SIDE EVENTS ONLY
 * test if the stix is indirectly related to the instance id (= relationship, refs)
 - depending on stix type (relation or sighting), we might search in different paths, aggregated
 */
export const testConnectedToSideEvents = (stix: any, filter: Filter) => {
  // only applies with "eq" operator
  if (filter.operator && filter.operator !== 'eq') {
    return false;
  }

  // advanced test between filter ids and the entity relations and refs
  // we shall aggregate all candidate fields and match the filter
  const aggregatedStixValues = [];
  if (stix.type === STIX_TYPE_RELATION) {
    aggregatedStixValues.push(...toValidArray(stix.target_ref)); // to
    aggregatedStixValues.push(...toValidArray(stix.source_ref)); // from
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    aggregatedStixValues.push(...(stix.where_sighted_refs ?? [])); // to
    aggregatedStixValues.push(...toValidArray(stix.sighting_of_ref)); // from
  }
  // refs
  aggregatedStixValues.push(...stixRefsExtractor(stix));

  return testStringFilter(filter, aggregatedStixValues);
};

/**
 * TODO: This mapping could be given by the schema, like we do with stix converters
 */
export const FILTER_KEY_TESTERS_MAP: Record<string, TesterFunction> = {
  // basic keys
  [ASSIGNEE_FILTER]: testAssignee,
  [CONFIDENCE_FILTER]: testConfidence,
  [CREATED_BY_FILTER]: testCreatedBy,
  [CREATOR_FILTER]: testCreator,
  [DETECTION_FILTER]: testDetection,
  [INDICATOR_FILTER]: testIndicatorTypes,
  [LABEL_FILTER]: testLabel,
  [MAIN_OBSERVABLE_TYPE_FILTER]: testMainObservableType,
  [MARKING_FILTER]: testMarkingFilter,
  [OBJECT_CONTAINS_FILTER]: testObjectContains,
  [PATTERN_FILTER]: testPattern,
  [PRIORITY_FILTER]: testPriority,
  [REVOKED_FILTER]: testRevoked,
  [SEVERITY_FILTER]: testSeverity,
  [SCORE_FILTER]: testScore,
  [TYPE_FILTER]: testEntityType,
  [WORKFLOW_FILTER]: testWorkflow,

  // special keys (more complex behavior)
  [CONNECTED_TO_INSTANCE_FILTER]: testConnectedTo, // instance trigger, direct events
  [CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER]: testConnectedToSideEvents, // instance trigger, side events
  [RELATION_FROM_FILTER]: testRelationFrom,
  [RELATION_FROM_TYPES_FILTER]: testRelationFromTypes,
  [RELATION_TO_FILTER]: testRelationTo,
  [RELATION_TO_TYPES_FILTER]: testRelationToTypes,
};
