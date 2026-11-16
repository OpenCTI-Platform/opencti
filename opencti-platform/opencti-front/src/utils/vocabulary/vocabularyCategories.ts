import type { VocabularyCategory } from '../hooks/__generated__/useVocabularyEntriesQuery.graphql';

// The members of the VocabularyCategory GraphQL enum (opencti-graphql/src/modules/vocabulary/vocabulary.graphql).
// Typed against the generated enum, so a name that leaves the schema fails the type check.
export const VOCABULARY_CATEGORIES: readonly VocabularyCategory[] = [
  'account_type_ov',
  'attack_motivation_ov',
  'attack_resource_level_ov',
  'case_severity_ov',
  'case_priority_ov',
  'channel_types_ov',
  'closing_reason_ov',
  'collection_layers_ov',
  'event_type_ov',
  'grouping_context_ov',
  'implementation_language_ov',
  'incident_response_types_ov',
  'incident_type_ov',
  'incident_severity_ov',
  'indicator_type_ov',
  'infrastructure_type_ov',
  'integrity_level_ov',
  'malware_capabilities_ov',
  'malware_result_ov',
  'malware_type_ov',
  'platforms_ov',
  'opinion_ov',
  'organization_type_ov',
  'pattern_type_ov',
  'permissions_ov',
  'processor_architecture_ov',
  'reliability_ov',
  'report_types_ov',
  'request_for_information_types_ov',
  'request_for_takedown_types_ov',
  'security_platform_type_ov',
  'service_status_ov',
  'service_type_ov',
  'start_type_ov',
  'system_category_ov',
  'system_criticality_ov',
  'system_environment_ov',
  'system_internet_facing_ov',
  'system_platform_ov',
  'system_subcategory_ov',
  'key_type_ov',
  'threat_actor_group_type_ov',
  'threat_actor_group_role_ov',
  'threat_actor_group_sophistication_ov',
  'threat_actor_individual_type_ov',
  'threat_actor_individual_role_ov',
  'threat_actor_individual_sophistication_ov',
  'tool_types_ov',
  'note_types_ov',
  'gender_ov',
  'marital_status_ov',
  'hair_color_ov',
  'eye_color_ov',
  'persona_type_ov',
  'coverage_ov',
];

const VOCABULARY_CATEGORY_SET: ReadonlySet<string> = new Set(VOCABULARY_CATEGORIES);

/**
 * Whether a name is a member of the VocabularyCategory enum.
 * A query variable outside the enum is rejected by GraphQL and the Relay request throws,
 * so only a name that passes this check may reach a vocabulary query.
 */
export const isVocabularyCategory = (name: string | null | undefined): name is VocabularyCategory => {
  return !!name && VOCABULARY_CATEGORY_SET.has(name);
};
