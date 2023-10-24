import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-extensions';
import { generateInternalType, getParentTypes } from '../../schema/schemaUtils';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../schema/general';
import type { Filter } from './stream-filters';
import { stixRefsExtractor } from '../../schema/stixEmbeddedRelationship';
import { generateStandardId } from '../../schema/identifier';

//-----------------------------------------------------------------------------------
/**
 * Apply the boolean logic of testing the equality of some candidate values to an array of values.
 * It applies to "eq" and "not_eq" operators as well as "nil" and "not_nil", but not to numeric operator (lt, gt , etc.)
 * @param filter the raw filter
 * @param adaptedFilterValues filter.values adapted to the boolean logic implemented (e.g. parsing values to boolean, forcing lowercase)
 * @param stixCandidates the values inside the stix bundle that we compare to the filter values
 */
export const testEqualityByMode = ({ mode, operator }: Pick<Filter, 'mode' | 'operator'>, adaptedFilterValues: (string | boolean)[], stixCandidates: (string | boolean)[]) => {
  // "(not) nil" or "(not) equal to nothing" is resolved the same way
  if (operator === 'nil' || (operator === 'eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length === 0;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length > 0;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (adaptedFilterValues.length === 0) {
    return false;
  }

  const allFound = adaptedFilterValues.every((v) => stixCandidates.includes(v));
  const oneFound = adaptedFilterValues.some((v) => stixCandidates.includes(v));

  if (mode === 'AND') {
    // we need to find all of them or none of them
    return (operator === 'eq' && allFound) || (operator === 'not_eq' && !oneFound);
  }
  if (mode === 'OR') {
    // we need to find one of them or at least one is not found
    return (operator === 'eq' && oneFound) || (operator === 'not_eq' && !allFound);
  }

  return false;
};

/**
 * Take a single value and return an array.
 * The array contains the value only if the value is defined, otherwise array is empty
 * Useful for using testEqualityByMode on a single stix value that might not be present
 */
const toValidArray = <T = unknown>(v: T) => {
  if (v !== undefined && v !== null) {
    return [v];
  }
  return [];
};

/**
 * Apply a boolean logic on some numeric values to compare (eq, gt, lt... etc)
 * The stix candidate is compared to an array of filter values according to filter mode and operator.
 * The candidate can be null if the value is not present in stix bundle.
 * @param filter the raw filter, we'll parse its values to number
 * @param stixCandidate the value inside the stix bundle that we compare to the filter values, might be null
 */
export const testNumericByMode = ({ mode, operator, values }: Pick<Filter, 'mode' | 'operator' | 'values'>, stixCandidate: number | null) => {
  const filterValuesAsNumbers = values.map((v) => parseInt(v, 10)).filter((n) => !Number.isNaN(n));

  if (operator === 'nil' || (operator === 'eq' && filterValuesAsNumbers.length === 0)) {
    return stixCandidate === null;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && filterValuesAsNumbers.length === 0)) {
    return stixCandidate !== null;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (stixCandidate === null) {
    return false;
  }

  if (mode === 'AND') {
    // value must compare to all candidates according to operator
    return (operator === 'eq' && filterValuesAsNumbers.every((c) => stixCandidate === c))
        || (operator === 'not_eq' && filterValuesAsNumbers.every((c) => stixCandidate !== c))
        || (operator === 'lt' && filterValuesAsNumbers.every((c) => stixCandidate < c))
        || (operator === 'lte' && filterValuesAsNumbers.every((c) => stixCandidate <= c))
        || (operator === 'gt' && filterValuesAsNumbers.every((c) => stixCandidate > c))
        || (operator === 'gte' && filterValuesAsNumbers.every((c) => stixCandidate >= c));
  }
  if (mode === 'OR') {
    // value must compare to at least one of the candidates according to operator
    return (operator === 'eq' && filterValuesAsNumbers.some((c) => stixCandidate === c))
      || (operator === 'not_eq' && filterValuesAsNumbers.some((c) => stixCandidate !== c))
      || (operator === 'lt' && filterValuesAsNumbers.some((c) => stixCandidate < c))
      || (operator === 'lte' && filterValuesAsNumbers.some((c) => stixCandidate <= c))
      || (operator === 'gt' && filterValuesAsNumbers.some((c) => stixCandidate > c))
      || (operator === 'gte' && filterValuesAsNumbers.some((c) => stixCandidate >= c));
  }

  return false;
};

//-----------------------------------------------------------------------------------
// Testers for each possible filter.
// The stix object format is sometimes very different from what we store internally
// and in our filters, so we need extra, specific steps.
// TODO: we use the type any for the stix object; we lack proper types to address this very complex model

/**
 * MARKINGS
 * - markedBy is object_marking_refs in stix
 */
export const testMarkingFilter = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.object_marking_refs ?? [];
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * ENTITY TYPES
 * - entity_type is type in stix (in extension or generated from stix data)
 * - we must also search in parent types
 */
export const testEntityType = (stix: any, filter: Filter) => {
  const stixValue: string = stix.extensions?.[STIX_EXT_OCTI]?.type ?? generateInternalType(stix);
  const extendedStixValues = [stixValue, ...getParentTypes(stixValue)];
  return testEqualityByMode(filter, filter.values, extendedStixValues);
};

/**
 * INDICATORS
  * - search must be insensitive to case due to constraint in frontend keywords (using "runtimeAttribute" based on keyword which is always lowercase)
 */
export const testIndicator = (stix: any, filter: Filter) => {
  const filterValuesInLowerCase = filter.values.map((v) => v.toLowerCase());
  const stixValues: string[] = (stix.indicator_types ?? []).map((v: string) => v.toLowerCase());
  return testEqualityByMode(filter, filterValuesInLowerCase, stixValues);
};

/**
 * MARKINGS
 * - x_opencti_workflow_id is workflow_id in stix (in extension)
 */
export const testWorkflow = (stix: any, filter: Filter) => {
  const stixValue = stix.extensions?.[STIX_EXT_OCTI].workflow_id;
  return testEqualityByMode(filter, filter.values, toValidArray(stixValue));
};

/**
 * CREATED BY
 * - createdBy is created_by_ref in stix (in first level or in extension)
 */
export const testCreatedBy = (stix: any, filter: Filter) => {
  const stixValue: string | undefined = stix.created_by_ref ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.created_by_ref;
  return testEqualityByMode(filter, filter.values, toValidArray(stixValue));
};

/**
 * TECHNICAL CREATORS
 * - creator is creator_ids in stix (in extension)
 */
export const testCreator = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI]?.creator_ids ?? [];
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * ASSIGNEES
 * - assigneeTo is assignee_ids in stix (in extension)
 */
export const testAssignee = (stix: any, filter: Filter) => {
  const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI]?.assignee_ids ?? [];
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * LABELS
 * - "no-label" is defined by using the operator nil (no longer a "fake" value with id=null)
 * - labelledBy is labels in stix (in first level or in extension)
 */
export const testLabel = (stix: any, filter: Filter) => {
  const stixValues: string[] = [...(stix.labels ?? []), ...(stix.extensions?.[STIX_EXT_OCTI_SCO]?.labels ?? [])];
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * REVOKED
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testRevoked = (stix: any, filter: Filter) => {
  // it would be stupid to have filter.values with both true and false
  // but we handle it anyway for consistency among the tester functions
  const filterValuesAsBooleans = filter.values.map((v) => v === 'true');
  const stixValues: boolean[] = toValidArray(stix.revoked);
  return testEqualityByMode(filter, filterValuesAsBooleans, stixValues);
};

/**
 * DETECTION
 * - x_opencti_detection is detection in stix extension
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testDetection = (stix: any, filter: Filter) => {
  const filterValuesAsBooleans = filter.values.map((v) => v === 'true');
  const stixValues: boolean[] = toValidArray(stix.extensions?.[STIX_EXT_OCTI]?.detection);
  return testEqualityByMode(filter, filterValuesAsBooleans, stixValues);
};

/**
 * SCORE
 * - x_opencti_score is x_opencti_score or score in stix (first level or extensions)
 * - numerical value stored in id that must be parsed from string
 */
export const testScore = (stix: any, filter: Filter) => {
  const stixValue: number | null = stix.x_opencti_score ?? stix.extensions?.[STIX_EXT_OCTI]?.score ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.score ?? null;
  return testNumericByMode(filter, stixValue);
};

/**
 * CONFIDENCE
 * - numerical value stored in id that must be parsed from string
 */
export const testConfidence = (stix: any, filter: Filter) => {
  const stixValue: number | null = stix.confidence ?? null;
  return testNumericByMode(filter, stixValue);
};

/**
 * PATTERN
 * - need lowercase comparison
 */
export const testPattern = (stix: any, filter: Filter) => {
  const filterValuesInLowerCase = filter.values.map((v) => v.toLowerCase());
  const stixValues: string[] = toValidArray(stix.pattern_type ? stix.pattern_type.toLowerCase() : null);
  return testEqualityByMode(filter, filterValuesInLowerCase, stixValues);
};

/**
 * MAIN OBSERVABLE TYPES
 * - x_opencti_main_observable_type is main_observable_type in stix extension
 * - need lowercase comparison
 */
export const testMainObservableType = (stix: any, filter: Filter) => {
  const filterValuesInLowerCase = filter.values.map((v) => v.toLowerCase());
  const stixValue = stix.extensions?.[STIX_EXT_OCTI]?.main_observable_type;
  const stixValues: string[] = toValidArray(stixValue ? stixValue.toLowerCase() : null);
  return testEqualityByMode(filter, filterValuesInLowerCase, stixValues);
};

/**
 * OBJECT CONTAINS
 * - objectContains is object_refs+object_refs_inferred in stix (first level and extension)
 */
export const testObjectContains = (stix: any, filter: Filter) => {
  const stixValues: string[] = [...(stix.object_refs ?? []), ...(stix.extensions?.[STIX_EXT_OCTI]?.object_refs_inferred ?? [])];
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * RELATION FROM
 * - depending on stix type (relation or sighting), we might search in source_ref or sighting_of_ref
 */
export const testRelationFrom = (stix: any, filter: Filter) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const stixValues: string[] = toValidArray(stix.source_ref);
    return testEqualityByMode(filter, filter.values, stixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = toValidArray(stix.sighting_of_ref);
    return testEqualityByMode(filter, filter.values, stixValues);
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
    return testEqualityByMode(filter, filter.values, stixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = stix.where_sighted_refs ?? [];
    return testEqualityByMode(filter, filter.values, stixValues);
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
    const stixValue = stix.extensions?.[STIX_EXT_OCTI].source_type;
    const extendedStixValues: string[] = [stixValue, ...getParentTypes(stixValue)];
    return testEqualityByMode(filter, filter.values, extendedStixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValue = stix.extensions?.[STIX_EXT_OCTI].sighting_of_type;
    const extendedStixValues: string[] = [stixValue, ...getParentTypes(stixValue)];
    return testEqualityByMode(filter, filter.values, extendedStixValues);
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
    const stixValue = stix.extensions?.[STIX_EXT_OCTI].target_type;
    const extendedStixValues: string[] = [stixValue, ...getParentTypes(stixValue)];
    return testEqualityByMode(filter, filter.values, extendedStixValues);
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    const stixValues: string[] = stix.extensions?.[STIX_EXT_OCTI].where_sighted_types || [];
    const extendedStixValues = [...stixValues, ...stixValues.map((t) => getParentTypes(t)).flat()];
    return testEqualityByMode(filter, filter.values, extendedStixValues);
  }
  return false;
};

/**
 * REFS
 * - uses a refs extractor using the standardId generator
 */
export const testRefs = (stix: any, filter: Filter) => {
  const stixValues: string[] = stixRefsExtractor(stix, generateStandardId);
  return testEqualityByMode(filter, filter.values, stixValues);
};

/**
 * INSTANCE TYPE (elementId)
 * - elementId is id in stix extension
 * - useSideEventMatching arg to optionally test against relations and refs of the object
 */
export const testInstanceType = (stix: any, filter: Filter, useSideEventMatching = false) => {
  const stixValues = toValidArray(stix.extensions?.[STIX_EXT_OCTI]?.id);
  if (!useSideEventMatching) {
    // basic equality test between ids
    return testEqualityByMode(filter, filter.values, stixValues);
  }

  // useSideEventMatching is set ; only applies with "eq" operator
  if (filter.operator !== 'eq') {
    return false;
  }
  // advanced test between filter ids and the entity relations and refs
  // TODO: this will only work properly with the mode=OR, as our testers work in isolation
  // In mode=AND, if filter.values=[X, Y] it will match only if X and Y are both found during one of the testers below
  // It won't match if X is found in a ref and Y in a relation (arguably, it should match as all filter values are found)
  return testRelationTo(stix, filter) || testRelationFrom(stix, filter) || testRefs(stix, filter);
};
