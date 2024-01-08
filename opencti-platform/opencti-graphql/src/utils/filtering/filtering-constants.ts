import { INPUT_LABELS } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';

// Resolved-Filters
// These require special handling when comparing to a stix object as they need to be resolved before comparison
// for instance, a filter on label would be { key: 'objectLabel', values: ["some-internal_id-for-a-label"], ... }
// but a stix object contains { labels: [ "labelA", "labelB"], ... }
// For this matter, we rely on the cache (key ENTITY_TYPE_RESOLVED_FILTERS)
export const LABEL_FILTER = INPUT_LABELS;
export const MARKING_FILTER = 'objectMarking';
export const CREATED_BY_FILTER = 'createdBy';
export const CREATOR_FILTER = 'creator_id';
export const ASSIGNEE_FILTER = 'objectAssignee';
export const PARTICIPANT_FILTER = 'objectParticipant';
export const OBJECT_CONTAINS_FILTER = 'objects';
export const RELATION_FROM_FILTER = 'fromId';
export const RELATION_TO_FILTER = 'toId';
export const INSTANCE_FILTER = 'elementId';
export const CONNECTED_TO_INSTANCE_FILTER = 'connectedToId';
export const CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER = 'connectedToId_sideEvents';

// Values that do not need resolution when matching against stix object
export const TYPE_FILTER = 'entity_type';
export const INDICATOR_FILTER = 'indicator_types';
export const SCORE_FILTER = 'x_opencti_score';
export const DETECTION_FILTER = 'x_opencti_detection';
export const SEVERITY_FILTER = 'severity';
export const PRIORITY_FILTER = 'priority';
export const X_OPENCTI_WORKFLOW_ID = 'x_opencti_workflow_id';
export const WORKFLOW_FILTER = 'workflow_id';
export const CONFIDENCE_FILTER = 'confidence';
export const REVOKED_FILTER = 'revoked';
export const PATTERN_FILTER = 'pattern_type';
export const MAIN_OBSERVABLE_TYPE_FILTER = 'x_opencti_main_observable_type';
export const RELATION_FROM_TYPES_FILTER = 'fromTypes';
export const RELATION_TO_TYPES_FILTER = 'toTypes';

// special cases
export const IDS_FILTER = 'ids';
export const SIGHTED_BY_FILTER = 'sightedBy';
export const CONNECTIONS_FILTER = 'connections';
export const RULE_FILTER = 'rule';
export const USER_ID_FILTER = 'user_id';
export const SOURCE_RELIABILITY_FILTER = 'source_reliability';

// for audit logging (Elastic + Stream)
export const CONTEXT_ENTITY_ID_FILTER = 'contextEntityId';
export const CONTEXT_ENTITY_TYPE_FILTER = 'contextEntityType';
export const CONTEXT_CREATOR_FILTER = 'contextCreator';
export const CONTEXT_CREATED_BY_FILTER = 'contextCreatedBy';
export const CONTEXT_OBJECT_MARKING_FILTER = 'contextObjectMarking';
export const CONTEXT_OBJECT_LABEL_FILTER = 'contextObjectLabel';
export const MEMBERS_USER_FILTER = 'members_user';
export const MEMBERS_GROUP_FILTER = 'members_group';
export const MEMBERS_ORGANIZATION_FILTER = 'members_organization';

// list of the special filtering keys
// (= key with a complex behavior, not belonging to the schema ref definition or the attribute definitions)
export const specialFilterKeys = [
  SIGHTED_BY_FILTER, // relation between elements linked by a stix sighting relationship
  INSTANCE_FILTER, // element involved in a relationship with the entity
  CONNECTIONS_FILTER, // for nested filters
  `rel_${RELATION_OBJECT}`,
  CREATOR_FILTER, // technical creator
  CONNECTED_TO_INSTANCE_FILTER, // listened instances for an instance trigger
  IDS_FILTER, // values should match any id (internal_id, standard_id, or stix_id)
  CONTEXT_ENTITY_ID_FILTER,
  CONTEXT_ENTITY_TYPE_FILTER,
  CONTEXT_CREATOR_FILTER,
  CONTEXT_CREATED_BY_FILTER,
  CONTEXT_OBJECT_MARKING_FILTER,
  CONTEXT_OBJECT_LABEL_FILTER,
  MEMBERS_USER_FILTER,
  MEMBERS_GROUP_FILTER,
  MEMBERS_ORGANIZATION_FILTER,
  RULE_FILTER, // for inference engine rules
  SOURCE_RELIABILITY_FILTER, // reliability of the author
  WORKFLOW_FILTER,
];

// nested filter keys also authorized in some elastic query cases (ex: retention policy query checking)
// but normally not-authorized in elastic queries (because they should be passed in options)
export const nestedFilterKeys = [
  RELATION_FROM_FILTER, // nested relation for the from of a relationship
  RELATION_TO_FILTER, // nested relation for the to of a relationship
  RELATION_FROM_TYPES_FILTER, // nested relation for the from type of a relationship
  RELATION_TO_TYPES_FILTER, // nested relation for the to type of a relationship
];

// list of filter keys that are not relation refs keys but whose values need to be resolved (= values point an entity with an id)
// used in findFiltersRepresentatives
export const specialFilterKeysWhoseValueToResolve = [
  SIGHTED_BY_FILTER, // relation between elements linked by a stix sighting relationship
  INSTANCE_FILTER, // element involved in a relationship with the entity
  `rel_${RELATION_OBJECT}`,
  CREATOR_FILTER, // technical creator
  RELATION_FROM_FILTER, // nested relation for the from of a relationship
  RELATION_TO_FILTER, // nested relation for the to of a relationship
  CONNECTED_TO_INSTANCE_FILTER, // listened instances for an instance trigger
  IDS_FILTER, // values should match any id (internal_id, standard_id, or stix_id)
  CONTEXT_ENTITY_ID_FILTER,
  CONTEXT_CREATOR_FILTER,
  CONTEXT_CREATED_BY_FILTER,
  CONTEXT_OBJECT_MARKING_FILTER,
  CONTEXT_OBJECT_LABEL_FILTER,
  USER_ID_FILTER,
  MEMBERS_USER_FILTER,
  MEMBERS_GROUP_FILTER,
  MEMBERS_ORGANIZATION_FILTER,
  RULE_FILTER, // for inference engine rules
  WORKFLOW_FILTER,
];
