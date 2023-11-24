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
export const WORKFLOW_FILTER = 'x_opencti_workflow_id';
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
export const MEMBERS_USER_FILTER = 'members_user';
export const MEMBERS_GROUP_FILTER = 'members_group';
export const MEMBERS_ORGANIZATION_FILTER = 'members_organization';
export const RULE_FILTER = 'rule';

// list of the special filtering keys (= key with a complex behavior, not belonging to the schema ref definition or the attribute definitions)
export const specialFilterKeys = [
  SIGHTED_BY_FILTER, // relation between elements linked by a stix sighting relationship
  INSTANCE_FILTER, // element involved in a relationship with the entity
  CONNECTIONS_FILTER, // for nested filters
  `rel_${RELATION_OBJECT}`,
  CREATOR_FILTER, // technical creator
  RELATION_FROM_FILTER, // nested relation for the from of a relationship
  RELATION_TO_FILTER, // nested relation for the to of a relationship
  RELATION_FROM_TYPES_FILTER, // nested relation for the from type of a relationship
  RELATION_TO_TYPES_FILTER, // nested relation for the to type of a relationship
  CONNECTED_TO_INSTANCE_FILTER, // listened instances for an instance trigger
  IDS_FILTER, // values should match any id (internal_id, standard_id, or stix_id)
  MEMBERS_USER_FILTER, // for activity trigger
  MEMBERS_GROUP_FILTER, // for activity trigger
  MEMBERS_ORGANIZATION_FILTER, // for activity trigger
  RULE_FILTER, // for inference engine rules
];
