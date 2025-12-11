// Mapping of attribute names to OpenVocab types
// This constant is used to identify which attributes should use OpenVocabField in forms

export interface VocabularyMapping {
  attribute: string;
  vocabularyType: string;
  label?: string;
  multiple?: boolean;
}

export const OPENVOCAB_FIELD_MAPPINGS: VocabularyMapping[] = [
  // Attack Pattern attributes
  { attribute: 'x_mitre_platforms', vocabularyType: 'platforms_ov', label: 'Platforms', multiple: true },
  { attribute: 'x_mitre_permissions_required', vocabularyType: 'permissions-ov', label: 'Required permissions', multiple: true },

  // Threat Actor attributes
  { attribute: 'threat_actor_types', vocabularyType: 'threat-actor-group-type-ov', label: 'Threat actor types', multiple: true },
  { attribute: 'sophistication', vocabularyType: 'threat-actor-group-sophistication-ov', label: 'Sophistication', multiple: false },
  { attribute: 'resource_level', vocabularyType: 'attack-resource-level-ov', label: 'Resource level', multiple: false },
  { attribute: 'primary_motivation', vocabularyType: 'attack-motivation-ov', label: 'Primary motivation', multiple: false },
  { attribute: 'secondary_motivations', vocabularyType: 'attack-motivation-ov', label: 'Secondary motivations', multiple: true },
  { attribute: 'goals', vocabularyType: 'threat-actor-group-goals-ov', label: 'Goals', multiple: true },
  { attribute: 'roles', vocabularyType: 'threat-actor-group-role-ov', label: 'Roles', multiple: true },

  // Threat Actor Individual attributes
  { attribute: 'personal_motivations', vocabularyType: 'attack-motivation-ov', label: 'Personal motivations', multiple: true },
  { attribute: 'eye_color', vocabularyType: 'eye-color-ov', label: 'Eye color', multiple: false },
  { attribute: 'hair_color', vocabularyType: 'hair-color-ov', label: 'Hair color', multiple: false },
  { attribute: 'marital_status', vocabularyType: 'marital-status-ov', label: 'Marital status', multiple: false },

  // Malware attributes
  { attribute: 'malware_types', vocabularyType: 'malware-type-ov', label: 'Malware types', multiple: true },
  { attribute: 'architecture_execution_envs', vocabularyType: 'processor-architecture-ov', label: 'Architecture execution env.', multiple: true },
  { attribute: 'implementation_languages', vocabularyType: 'implementation-language-ov', label: 'Implementation languages', multiple: true },
  { attribute: 'capabilities', vocabularyType: 'malware-capabilities-ov', label: 'Capabilities', multiple: true },

  // Case attributes
  { attribute: 'severity', vocabularyType: 'case_severity_ov', label: 'Severity', multiple: false },
  { attribute: 'priority', vocabularyType: 'case_priority_ov', label: 'Priority', multiple: false },
  { attribute: 'response_types', vocabularyType: 'incident_response_types_ov', label: 'Response types', multiple: true },
  { attribute: 'request_for_information_types', vocabularyType: 'request_for_information_types_ov', label: 'Request for information types', multiple: true },
  { attribute: 'request_for_takedown_types', vocabularyType: 'request_for_takedown_types_ov', label: 'Request for takedown types', multiple: true },

  // Report attributes
  { attribute: 'report_types', vocabularyType: 'report_types_ov', label: 'Report types', multiple: true },

  // Grouping attributes
  { attribute: 'context', vocabularyType: 'grouping-context-ov', label: 'Context', multiple: false },

  // Opinion attributes
  { attribute: 'opinion', vocabularyType: 'opinion-ov', label: 'Opinion', multiple: false },

  // Event attributes
  { attribute: 'event_types', vocabularyType: 'event_type_ov', label: 'Event types', multiple: true },

  // Incident attributes
  { attribute: 'incident_type', vocabularyType: 'incident-type-ov', label: 'Incident type', multiple: false },

  // Infrastructure attributes
  { attribute: 'infrastructure_types', vocabularyType: 'infrastructure_type_ov', label: 'Infrastructure types', multiple: true },

  // Indicator attributes
  { attribute: 'pattern_type', vocabularyType: 'pattern_type_ov', label: 'Pattern type', multiple: false },
  { attribute: 'indicator_types', vocabularyType: 'indicator_type_ov', label: 'Indicator types', multiple: true },

  // Data Source attributes
  { attribute: 'collection_layers', vocabularyType: 'collection_layers_ov', label: 'Layers', multiple: true },

  // Channel attributes
  { attribute: 'channel_types', vocabularyType: 'channel_type_ov', label: 'Channel types', multiple: true },

  // Tool attributes
  { attribute: 'tool_types', vocabularyType: 'tool_type_ov', label: 'Tool types', multiple: true },

  // Organization attributes
  { attribute: 'x_opencti_organization_type', vocabularyType: 'organization_type_ov', label: 'Organization type', multiple: false },

  // Security Platform attributes
  { attribute: 'security_platform_type', vocabularyType: 'security_platform_type_ov', label: 'Security platform type', multiple: false },

  // General attributes
  { attribute: 'x_opencti_reliability', vocabularyType: 'reliability_ov', label: 'Reliability', multiple: false },

  // Malware Analysis attributes
  { attribute: 'result_name', vocabularyType: 'malware_result_ov', label: 'Result name', multiple: false },

  // Note attributes
  { attribute: 'note_types', vocabularyType: 'note_types_ov', label: 'Note types', multiple: true },

  // Individual attributes
  { attribute: 'x_opencti_reliability', vocabularyType: 'reliability_ov', label: 'Reliability', multiple: false },

  // Ingestion RSS attributes
  { attribute: 'ingestion_running', vocabularyType: 'ingestion_running_ov', label: 'Ingestion running', multiple: false },
];

/**
 * Get vocabulary mapping by attribute name
 */
export const getVocabularyMappingByAttribute = (attribute: string): VocabularyMapping | undefined => {
  return OPENVOCAB_FIELD_MAPPINGS.find((mapping) => mapping.attribute === attribute);
};

/**
 * Check if an attribute should use OpenVocabField
 */
export const isOpenVocabAttribute = (attribute: string): boolean => {
  return OPENVOCAB_FIELD_MAPPINGS.some((mapping) => mapping.attribute === attribute);
};

/**
 * Get all attributes that use OpenVocabField
 */
export const getOpenVocabAttributes = (): string[] => {
  return OPENVOCAB_FIELD_MAPPINGS.map((mapping) => mapping.attribute);
};
