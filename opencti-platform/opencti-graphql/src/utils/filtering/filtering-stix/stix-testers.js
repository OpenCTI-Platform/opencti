import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-extensions';
import { generateInternalType, getParentTypes } from '../../../schema/schemaUtils';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../schema/general';
import { stixRefsExtractor } from '../../../schema/stixEmbeddedRelationship';
import { testStringFilter, testNumericFilter, toValidArray, testBooleanFilter } from '../boolean-logic-engine';
import { ASSIGNEE_FILTER, CONFIDENCE_FILTER, CONNECTED_TO_INSTANCE_FILTER, CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER, CREATED_BY_FILTER, CREATOR_FILTER, DETECTION_FILTER, INDICATOR_FILTER, LABEL_FILTER, MAIN_OBSERVABLE_TYPE_FILTER, MARKING_FILTER, OBJECT_CONTAINS_FILTER, PATTERN_FILTER, PRIORITY_FILTER, RELATION_FROM_FILTER, RELATION_FROM_TYPES_FILTER, RELATION_TO_FILTER, RELATION_TO_TYPES_FILTER, REVOKED_FILTER, SCORE_FILTER, SEVERITY_FILTER, TYPE_FILTER, WORKFLOW_FILTER } from '../filtering-constants';
//-----------------------------------------------------------------------------------
// Testers for each possible filter.
// The stix object format is sometimes very different from what we store internally
// and in our filters, so we need extra, specific steps.
// TODO: we use the type any for the stix object; we lack proper types to address this very complex model
/**
 * MARKINGS
 * - objectMarking is object_marking_refs in stix
 */
export const testMarkingFilter = (stix, filter) => {
    var _a;
    const stixValues = (_a = stix.object_marking_refs) !== null && _a !== void 0 ? _a : [];
    return testStringFilter(filter, stixValues);
};
/**
 * ENTITY TYPES
 * - entity_type is type in stix (in extension or generated from stix data)
 * - we must also search in parent types
 */
export const testEntityType = (stix, filter) => {
    var _a, _b, _c;
    const stixValue = (_c = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.type) !== null && _c !== void 0 ? _c : generateInternalType(stix);
    const extendedStixValues = [stixValue, ...getParentTypes(stixValue)];
    return testStringFilter(filter, extendedStixValues);
};
/**
 * INDICATORS
 * - search must be insensitive to case due to constraint in frontend keywords (using "runtimeAttribute" based on keyword which is always lowercase)
 */
export const testIndicatorTypes = (stix, filter) => {
    var _a;
    const stixValues = (_a = stix.indicator_types) !== null && _a !== void 0 ? _a : [];
    return testStringFilter(filter, stixValues);
};
/**
 * WORKFLOWS
 * - x_opencti_workflow_id is workflow_id in stix (in extension)
 */
export const testWorkflow = (stix, filter) => {
    var _a;
    const stixValue = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI].workflow_id;
    return testStringFilter(filter, toValidArray(stixValue));
};
/**
 * CREATED BY
 * - createdBy is created_by_ref in stix (in first level or in extension)
 */
export const testCreatedBy = (stix, filter) => {
    var _a, _b;
    const stixValues = [...toValidArray(stix.created_by_ref), ...toValidArray((_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI_SCO]) === null || _b === void 0 ? void 0 : _b.created_by_ref)];
    return testStringFilter(filter, stixValues);
};
/**
 * TECHNICAL CREATORS
 * - creator is creator_ids in stix (in extension)
 */
export const testCreator = (stix, filter) => {
    var _a, _b, _c;
    const stixValues = (_c = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.creator_ids) !== null && _c !== void 0 ? _c : [];
    return testStringFilter(filter, stixValues);
};
/**
 * ASSIGNEES
 * - assigneeTo is assignee_ids in stix (in extension)
 */
export const testAssignee = (stix, filter) => {
    var _a, _b, _c;
    const stixValues = (_c = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.assignee_ids) !== null && _c !== void 0 ? _c : [];
    return testStringFilter(filter, stixValues);
};
/**
 * LABELS
 * - "no-label" is defined by using the operator nil (no longer a "fake" value with id=null)
 * - labelledBy is labels in stix (in first level or in extension)
 */
export const testLabel = (stix, filter) => {
    var _a, _b, _c, _d;
    const stixValues = [...((_a = stix.labels) !== null && _a !== void 0 ? _a : []), ...((_d = (_c = (_b = stix.extensions) === null || _b === void 0 ? void 0 : _b[STIX_EXT_OCTI_SCO]) === null || _c === void 0 ? void 0 : _c.labels) !== null && _d !== void 0 ? _d : [])];
    return testStringFilter(filter, stixValues);
};
/**
 * REVOKED
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testRevoked = (stix, filter) => {
    const stixValue = stix.revoked;
    return testBooleanFilter(filter, stixValue);
};
/**
 * DETECTION
 * - x_opencti_detection is detection in stix extension
 * - boolean stored in id that must be parsed from string "true" or "false"
 */
export const testDetection = (stix, filter) => {
    var _a, _b;
    const stixValue = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.detection;
    return testBooleanFilter(filter, stixValue);
};
/**
 * SCORE
 * - x_opencti_score is x_opencti_score or score in stix (first level or extensions)
 * - numerical value stored in id that must be parsed from string
 */
export const testScore = (stix, filter) => {
    var _a, _b, _c, _d, _e, _f, _g;
    // path depends on entity type
    // do not take all possible scores in stix, we implement a priority order
    const stixValue = (_g = (_d = (_a = stix.x_opencti_score) !== null && _a !== void 0 ? _a : (_c = (_b = stix.extensions) === null || _b === void 0 ? void 0 : _b[STIX_EXT_OCTI]) === null || _c === void 0 ? void 0 : _c.score) !== null && _d !== void 0 ? _d : (_f = (_e = stix.extensions) === null || _e === void 0 ? void 0 : _e[STIX_EXT_OCTI_SCO]) === null || _f === void 0 ? void 0 : _f.score) !== null && _g !== void 0 ? _g : null;
    return testNumericFilter(filter, stixValue);
};
/**
 * CONFIDENCE
 * - numerical value stored in id that must be parsed from string
 */
export const testConfidence = (stix, filter) => {
    var _a;
    const stixValue = (_a = stix.confidence) !== null && _a !== void 0 ? _a : null;
    return testNumericFilter(filter, stixValue);
};
/**
 * PATTERN
 */
export const testPattern = (stix, filter) => {
    const stixValues = toValidArray(stix.pattern_type);
    return testStringFilter(filter, stixValues);
};
/**
 * MAIN OBSERVABLE TYPES
 * - x_opencti_main_observable_type is main_observable_type in stix extension
 */
export const testMainObservableType = (stix, filter) => {
    var _a, _b;
    const stixValues = toValidArray((_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI]) === null || _b === void 0 ? void 0 : _b.main_observable_type);
    return testStringFilter(filter, stixValues);
};
/**
 * OBJECT CONTAINS
 * - objectContains is object_refs+object_refs_inferred in stix (first level and extension)
 */
export const testObjectContains = (stix, filter) => {
    var _a, _b, _c, _d;
    const stixValues = [...((_a = stix.object_refs) !== null && _a !== void 0 ? _a : []), ...((_d = (_c = (_b = stix.extensions) === null || _b === void 0 ? void 0 : _b[STIX_EXT_OCTI]) === null || _c === void 0 ? void 0 : _c.object_refs_inferred) !== null && _d !== void 0 ? _d : [])];
    return testStringFilter(filter, stixValues);
};
/**
 * SEVERITY
 */
export const testSeverity = (stix, filter) => {
    const stixValues = toValidArray(stix.severity);
    return testStringFilter(filter, stixValues);
};
/**
 * PRIORITY
 */
export const testPriority = (stix, filter) => {
    const stixValues = toValidArray(stix.priority);
    return testStringFilter(filter, stixValues);
};
/**
 * RELATION FROM
 * - depending on stix type (relation or sighting), we might search in source_ref or sighting_of_ref
 */
export const testRelationFrom = (stix, filter) => {
    if (stix.type === STIX_TYPE_RELATION) {
        const stixValues = toValidArray(stix.source_ref);
        return testStringFilter(filter, stixValues);
    }
    if (stix.type === STIX_TYPE_SIGHTING) {
        const stixValues = toValidArray(stix.sighting_of_ref);
        return testStringFilter(filter, stixValues);
    }
    return false;
};
/**
 * RELATION FROM
 * - depending on stix type (relation or sighting), we might search in target_ref or where_sighted_refs (plurals!)
 */
export const testRelationTo = (stix, filter) => {
    var _a;
    if (stix.type === STIX_TYPE_RELATION) {
        const stixValues = toValidArray(stix.target_ref);
        return testStringFilter(filter, stixValues);
    }
    if (stix.type === STIX_TYPE_SIGHTING) {
        const stixValues = (_a = stix.where_sighted_refs) !== null && _a !== void 0 ? _a : [];
        return testStringFilter(filter, stixValues);
    }
    return false;
};
/**
 * RELATION FROM TYPES
 * - depending on stix type (relation or sighting), we might search in source_type or sighting_of_type (in extension)
 * - we must also search in parent types
 */
export const testRelationFromTypes = (stix, filter) => {
    var _a, _b, _c, _d;
    if (stix.type === STIX_TYPE_RELATION) {
        const stixValue = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI].source_type) !== null && _b !== void 0 ? _b : [];
        const extendedStixValues = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
        return testStringFilter(filter, extendedStixValues);
    }
    if (stix.type === STIX_TYPE_SIGHTING) {
        const stixValue = (_d = (_c = stix.extensions) === null || _c === void 0 ? void 0 : _c[STIX_EXT_OCTI].sighting_of_type) !== null && _d !== void 0 ? _d : [];
        const extendedStixValues = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
        return testStringFilter(filter, extendedStixValues);
    }
    return false;
};
/**
 * RELATION TO TYPES
 * - depending on stix type (relation or sighting), we might search in target_type or where_sighted_types (in extension)
 * - we must also search in parent types
 */
export const testRelationToTypes = (stix, filter) => {
    var _a, _b, _c, _d;
    if (stix.type === STIX_TYPE_RELATION) {
        const stixValue = (_b = (_a = stix.extensions) === null || _a === void 0 ? void 0 : _a[STIX_EXT_OCTI].target_type) !== null && _b !== void 0 ? _b : [];
        const extendedStixValues = [...toValidArray(stixValue), ...getParentTypes(stixValue)];
        return testStringFilter(filter, extendedStixValues);
    }
    if (stix.type === STIX_TYPE_SIGHTING) {
        const stixValues = (_d = (_c = stix.extensions) === null || _c === void 0 ? void 0 : _c[STIX_EXT_OCTI].where_sighted_types) !== null && _d !== void 0 ? _d : [];
        const extendedStixValues = [...stixValues, ...stixValues.map((t) => getParentTypes(t)).flat()];
        return testStringFilter(filter, extendedStixValues);
    }
    return false;
};
/**
 * CONNECTED TO for DIRECT EVENTS ONLY
 * test if the stix is directly related to the instance id
 */
export const testConnectedTo = (stix, filter) => {
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
export const testConnectedToSideEvents = (stix, filter) => {
    var _a;
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
        aggregatedStixValues.push(...((_a = stix.where_sighted_refs) !== null && _a !== void 0 ? _a : [])); // to
        aggregatedStixValues.push(...toValidArray(stix.sighting_of_ref)); // from
    }
    // refs
    aggregatedStixValues.push(...stixRefsExtractor(stix));
    return testStringFilter(filter, aggregatedStixValues);
};
/**
 * TODO: This mapping could be given by the schema, like we do with stix converters
 */
export const FILTER_KEY_TESTERS_MAP = {
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
