import { INPUT_LABELS } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { isMetricsName } from '../../modules/metrics/metrics-utils';

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
export const AUTHORIZED_FILTER = 'objectAuthorized';
export const OBJECT_CONTAINS_FILTER = 'objects';
export const RELATION_TO_SIGHTING_FILTER = 'toSightingId';
// ---- entities
export const INSTANCE_REGARDING_OF = 'regardingOf'; // Combination of relationship types and id for entity filtering
export const INSTANCE_DYNAMIC_REGARDING_OF = 'dynamicRegardingOf'; // Combination of relationship types and id for entity filtering
export const INSTANCE_REGARDING_OF_DIRECTION_FORCED = 'direction_forced';
export const INSTANCE_REGARDING_OF_DIRECTION_REVERSE = 'direction_reverse';
// ---- relationships
// TODO remove and migration in favor of exploiting directly 'connections' in the relationship model
export const RELATION_FROM_FILTER = 'fromId';
export const RELATION_DYNAMIC_FROM_FILTER = 'dynamicFrom';
export const RELATION_TO_FILTER = 'toId';
export const RELATION_DYNAMIC_TO_FILTER = 'dynamicTo';
export const INSTANCE_RELATION_FILTER = 'fromOrToId'; // Use for relationship context, renamed from entityId
export const RELATION_FROM_ROLE_FILTER = 'fromRole';
export const RELATION_TO_ROLE_FILTER = 'toRole';
export const RELATION_FROM_TYPES_FILTER = 'fromTypes';
export const RELATION_TO_TYPES_FILTER = 'toTypes';
export const REPRESENTATIVE_FILTER = 'representative'; // representative of an entity
export const INSTANCE_RELATION_TYPES_FILTER = 'elementWithTargetTypes'; // TODO Rename/migrate to fromOrToType
export const CONNECTED_TO_INSTANCE_FILTER = 'connectedToId'; // TODO Rename/migrate to triggerListenId
export const CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER = 'connectedToId_sideEvents';

// regardingOf filter subfilter keys
export const RELATION_DYNAMIC_SUBFILTER = 'dynamic';
export const RELATION_TYPE_SUBFILTER = 'relationship_type';
export const ID_SUBFILTER = 'id';
export const RELATION_INFERRED_SUBFILTER = 'is_inferred';

// Values that do not need resolution when matching against stix object
export const TYPE_FILTER = 'entity_type';
export const RELATION_TYPE_FILTER = 'relationship_type';
export const INDICATOR_FILTER = 'indicator_types';
export const SCORE_FILTER = 'x_opencti_score';
export const DETECTION_FILTER = 'x_opencti_detection';
export const SEVERITY_FILTER = 'severity';
export const PRIORITY_FILTER = 'priority';
export const X_OPENCTI_WORKFLOW_ID = 'x_opencti_workflow_id';
export const WORKFLOW_FILTER = 'workflow_id';
export const CONFIDENCE_FILTER = 'confidence';
export const REVOKED_FILTER = 'revoked';
export const PATTERN_TYPE_FILTER = 'pattern_type';
export const PATTERN_FILTER = 'pattern';
export const MAIN_OBSERVABLE_TYPE_FILTER = 'x_opencti_main_observable_type';
export const CISA_KEV_FILTER = 'x_opencti_cisa_kev';
export const EPSS_PERCENTILE_FILTER = 'x_opencti_epss_percentile';
export const EPSS_SCORE_FILTER = 'x_opencti_epss_score';
export const CVSS_BASE_SCORE_FILTER = 'x_opencti_cvss_base_score';
export const CVSS_BASE_SEVERITY_FILTER = 'x_opencti_cvss_base_severity';
export const REPORT_TYPES_FILTER = 'report_types';
export const INCIDENT_RESPONSE_TYPES_FILTER = 'response_types';
export const REQUEST_FOR_INFORMATION_TYPES_FILTER = 'information_types';
export const REQUEST_FOR_TAKEDOWN_TYPES_FILTER = 'takedown_types';
export const NOTE_TYPES_FILTER = 'note_types';
export const INCIDENT_TYPE_FILTER = 'incident_type';

// special cases
export const IDS_FILTER = 'ids';
export const SIGHTED_BY_FILTER = 'sightedBy';
export const CONNECTIONS_FILTER = 'connections';
export const RULE_FILTER = 'rule';
export const USER_ID_FILTER = 'user_id';
export const SOURCE_RELIABILITY_FILTER = 'source_reliability';
export const COMPUTED_RELIABILITY_FILTER = 'computed_reliability';
export const BULK_SEARCH_KEYWORDS_FILTER = 'bulkSearchKeywords';

// for opinions
export const OPINIONS_METRICS_MEAN_FILTER = 'opinionsMetricsMean';
export const OPINIONS_METRICS_MAX_FILTER = 'opinionsMetricsMax';
export const OPINIONS_METRICS_MIN_FILTER = 'opinionsMetricsMin';
export const OPINIONS_METRICS_TOTAL_FILTER = 'opinionsMetricsTotal';

// for audit logging (Elastic + Stream)
export const CONTEXT_ENTITY_ID_FILTER = 'contextEntityId'; // 'context_data.id'
export const CONTEXT_ENTITY_TYPE_FILTER = 'contextEntityType';
export const CONTEXT_CREATOR_FILTER = 'contextCreator';
export const CONTEXT_CREATED_BY_FILTER = 'contextCreatedBy';
export const CONTEXT_OBJECT_MARKING_FILTER = 'contextObjectMarking';
export const CONTEXT_OBJECT_LABEL_FILTER = 'contextObjectLabel';
export const MEMBERS_USER_FILTER = 'members_user';
export const MEMBERS_GROUP_FILTER = 'members_group';
export const MEMBERS_ORGANIZATION_FILTER = 'members_organization';
export const ALIAS_FILTER = 'alias'; // handle both 'aliases' and 'x_opencti_aliases' attributes
export const IS_INFERRED_FILTER = 'is_inferred'; // if an entity or relationship is inferred

// for PIR
export const PIR_SCORE_FILTER = 'pir_score';
export const LAST_PIR_SCORE_DATE_FILTER = 'last_pir_score_date';

// for users
export const USER_SERVICE_ACCOUNT_FILTER = 'user_service_account';

const COMPLEX_CONVERSION_FILTER_KEYS = [
  IDS_FILTER, // values should match any id (internal_id, standard_id, or stix_id)
  TYPE_FILTER, // values should match any parent_types
  RELATION_TYPE_FILTER, // values should match any parent_types
  INSTANCE_REGARDING_OF,
  INSTANCE_DYNAMIC_REGARDING_OF,
  RELATION_DYNAMIC_FROM_FILTER,
  RELATION_DYNAMIC_TO_FILTER,
  WORKFLOW_FILTER, // values should match the parent workflow pattern id
  X_OPENCTI_WORKFLOW_ID, // values should match the parent workflow pattern id
  SOURCE_RELIABILITY_FILTER, // reliability of the author
  COMPUTED_RELIABILITY_FILTER, // reliability, or reliability of the author if no reliability
  INSTANCE_RELATION_FILTER, // nested relation for the from or to of a relationship
  INSTANCE_RELATION_TYPES_FILTER, // nested relation for the from or to type of a relationship
  RELATION_FROM_FILTER, // nested relation for the from of a relationship
  RELATION_TO_FILTER, // nested relation for the to of a relationship
  RELATION_TO_SIGHTING_FILTER, // nested sighting relation for the to of a sighting
  RELATION_FROM_TYPES_FILTER, // nested relation for the from type of a relationship
  RELATION_TO_TYPES_FILTER, // nested relation for the to type of a relationship
  RELATION_FROM_ROLE_FILTER, // nested relation for the from role of a relationship
  RELATION_TO_ROLE_FILTER, // nested relation for the to role of a relationship
  ALIAS_FILTER, // key that target both the 'aliases' and 'x_opencti_aliases' attributes
  IS_INFERRED_FILTER, // if an entity or relationship is inferred
  USER_SERVICE_ACCOUNT_FILTER, // if the user is technical or not
  'authorized_members', // nested filter on restricted members => kept for retro compatibility (TODO remove after renaming)
  'authorized_members.id', // nested filter on restricted members => kept for retro compatibility (TODO remove after renaming)
  'restricted_members.id', // nested filter on restricted members
  BULK_SEARCH_KEYWORDS_FILTER, // set of keywords used in bulk search
  PIR_SCORE_FILTER, // should be associated to Pir Ids
  LAST_PIR_SCORE_DATE_FILTER, // should be associated to Pir Ids
];

export const isComplexConversionFilterKey = (filterKey: string) => {
  return COMPLEX_CONVERSION_FILTER_KEYS.includes(filterKey)
    || isMetricsName(filterKey);
};

// list of the special filtering keys
// (= key with a complex behavior, not belonging to the schema ref definition or the attribute definitions)
export const SPECIAL_FILTER_KEYS = [
  SIGHTED_BY_FILTER, // relation between elements linked by a stix sighting relationship
  CONNECTIONS_FILTER, // for nested filters
  `rel_${RELATION_OBJECT}`,
  CREATOR_FILTER, // technical creator
  CONNECTED_TO_INSTANCE_FILTER, // listened instances for an instance trigger
  OPINIONS_METRICS_MEAN_FILTER,
  OPINIONS_METRICS_MAX_FILTER,
  OPINIONS_METRICS_MIN_FILTER,
  OPINIONS_METRICS_TOTAL_FILTER,
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
  ...COMPLEX_CONVERSION_FILTER_KEYS,
];

// list of filter keys that are not relation refs keys but whose values need to be resolved (= values point an entity with an id)
// used in findFiltersRepresentatives
export const SPECIAL_FILTER_KEYS_WHOSE_VALUE_TO_RESOLVE = [
  SIGHTED_BY_FILTER, // relation between elements linked by a stix sighting relationship
  INSTANCE_REGARDING_OF,
  INSTANCE_DYNAMIC_REGARDING_OF,
  RELATION_DYNAMIC_FROM_FILTER,
  RELATION_DYNAMIC_TO_FILTER,
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
  INSTANCE_RELATION_FILTER,
  RELATION_FROM_FILTER,
  RELATION_TO_FILTER,
  RELATION_MEMBER_OF,
  RELATION_PARTICIPATE_TO,
];

// special filter values
export const ME_FILTER_VALUE = '@me';
export const FILTER_KEYS_WITH_ME_VALUE = [
  ASSIGNEE_FILTER,
  PARTICIPANT_FILTER,
  CONTEXT_CREATOR_FILTER,
  CREATOR_FILTER,
  CONTEXT_ENTITY_ID_FILTER,
  MEMBERS_USER_FILTER,
];

// multi filter keys
export const BULK_SEARCH_KEYWORDS_FILTER_KEYS = [
  'name',
  'aliases',
  'x_opencti_aliases',
  'x_mitre_id',
  'value',
  'subject',
  'attribute_abstract',
  'x_opencti_additional_names',
  // observables
  'iban',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'url',
  'card_number',
  'account_type',
  'user_id',
  'account_login',
  'path',
  'attribute_key',
  'persona_name',
];
