import { ChatPromptTemplate, FewShotChatMessagePromptTemplate } from '@langchain/core/prompts';
import { z } from 'zod';

// TODO Cathia (pas duppliquer les keys des autres fitres indiques)
const FilterTypeEnum = z.enum([
  'created_at',
  'updated_at',
  'creator_id',
  'opinions_metrics.mean',
  'opinions_metrics.max',
  'opinions_metrics.min',
  'opinions_metrics.total',
  'createdBy',
  'objectMarking',
  'objectLabel',
  'externalReferences',
  'computed_reliability',
  'objects',
  'workflow_id',
  'created',
  'confidence',
  'name',
  'description',
  'x_mitre_platforms',
  'x_mitre_permissions_required',
  'x_mitre_detection',
  'killChainPhases',
  'alias',
  'first_seen',
  'last_seen',
  'objective',
  'objectOrganization',
  'attribute_abstract',
  'content',
  'note_types',
  'likelihood',
  'first_observed',
  'last_observed',
  'number_observed',
  'explanation',
  'opinion',
  'report_types',
  'published',
  'objectParticipant',
  'x_mitre_id',
  'x_opencti_threat_hunting',
  'x_opencti_log_sources',
  'contact_information',
  'infrastructure_types',
  'goals',
  'resource_level',
  'primary_motivation',
  'secondary_motivations',
  'postal_code',
  'street_address',
  'malware_types',
  'is_family',
  'architecture_execution_envs',
  'implementation_languages',
  'capabilities',
  'samples',
  'operatingSystems',
  'threat_actor_types',
  'roles',
  'sophistication',
  'tool_types',
  'tool_version',
  'x_opencti_cvss_base_score',
  'x_opencti_cvss_base_severity',
  'x_opencti_cvss_attack_vector',
  'x_opencti_cvss_integrity_impact',
  'x_opencti_cvss_availability_impact',
  'x_opencti_cvss_confidentiality_impact',
  'x_opencti_cisa_kev',
  'x_opencti_epss_score',
  'x_opencti_epss_percentile',
  'incident_type',
  'severity',
  'source',
  'channel_types',
  'event_types',
  'start_time',
  'stop_time',
  'context',
  'narrative_types',
  'dataSource',
  'collection_layers',
  'due_date',
  'priority',
  'response_types',
  'information_types',
  'takedown_types',
  'rating',
  'product',
  'version',
  'configuration_version',
  'modules',
  'analysis_engine_version',
  'analysis_definition_version',
  'submitted',
  'analysis_started',
  'analysis_ended',
  'result',
  'hostVm',
  'operatingSystem',
  'installedSoftware',
  'analysisSco',
  'analysisSample',
  'revoked',
  'personal_motivations',
  'date_of_birth',
  'gender',
  'job_title',
  'marital_status',
  'eye_color',
  'hair_color',
  'bornIn',
  'ethnicity',
  'pattern_type',
  'pattern',
  'indicator_types',
  'valid_from',
  'valid_until',
  'x_opencti_score',
  'x_opencti_detection',
  'x_opencti_main_observable_type',
  'x_opencti_organization_type',
  'x_opencti_description',
  'number',
  'rir',
  'path',
  'path_enc',
  'ctime',
  'mtime',
  'atime',
  'containsObservable',
  'value',
  'resolvesTo',
  'display_name',
  'belongsTo',
  'is_multipart',
  'attribute_date',
  'content_type',
  'message_id',
  'subject',
  'received_lines',
  'body',
  'emailFrom',
  'emailSender',
  'emailTo',
  'emailCc',
  'emailBcc',
  'bodyMultipart',
  'rawEmail',
  'content_disposition',
  'bodyRaw',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'hashes.SSDEEP',
  'mime_type',
  'payload_bin',
  'url',
  'encryption_algorithm',
  'decryption_key',
  'x_opencti_additional_names',
  'extensions',
  'size',
  'name_enc',
  'magic_number_hex',
  'parentDirectory',
  'obsContent',
  'is_self_signed',
  'serial_number',
  'signature_algorithm',
  'issuer',
  'validity_not_before',
  'validity_not_after',
  'subject_public_key_algorithm',
  'subject_public_key_modulus',
  'subject_public_key_exponent',
  'basic_constraints',
  'name_constraints',
  'policy_constraints',
  'key_usage',
  'extended_key_usage',
  'subject_key_identifier',
  'authority_key_identifier',
  'subject_alternative_name',
  'issuer_alternative_name',
  'subject_directory_attributes',
  'crl_distribution_points',
  'inhibit_any_policy',
  'private_key_usage_period_not_before',
  'private_key_usage_period_not_after',
  'certificate_policies',
  'policy_mappings',
  'start',
  'end',
  'is_active',
  'src_port',
  'dst_port',
  'protocols',
  'src_byte_count',
  'dst_byte_count',
  'src_packets',
  'dst_packets',
  'networkSrc',
  'networkDst',
  'srcPayload',
  'dstPayload',
  'networkEncapsulates',
  'encapsulatedBy',
  'is_hidden',
  'pid',
  'created_time',
  'cwd',
  'command_line',
  'environment_variables',
  'aslr_enabled',
  'dep_enabled',
  'owner_sid',
  'window_title',
  'integrity_level',
  'service_name',
  'descriptions',
  'group_name',
  'start_type',
  'service_type',
  'service_status',
  'openedConnections',
  'creatorUser',
  'processImage',
  'processParent',
  'processChild',
  'serviceDlls',
  'cpe',
  'swid',
  'languages',
  'vendor',
  'user_id',
  'credential',
  'account_login',
  'account_type',
  'is_service_account',
  'is_privileged',
  'can_escalate_privs',
  'is_disabled',
  'account_created',
  'account_expires',
  'credential_last_changed',
  'account_first_login',
  'account_last_login',
  'attribute_key',
  'modified_time',
  'number_of_subkeys',
  'winRegValues',
  'data',
  'data_type',
  'iban',
  'bic',
  'account_number',
  'card_number',
  'expiration_date',
  'cvv',
  'holder_name',
  'title',
  'media_category',
  'publication_date',
  'persona_name',
  'persona_type',
  'relationship_type',
  // "id"
]);

const RelationshipTypeEnum = z.enum([
  'attributed-to',
  'exploits',
  'has',
  'indicates',
  'located-at',
  'originates-from',
  'part-of',
  'related-to',
  'subtechnique-of',
  'targets',
  'uses',
]);

const EntityTypeEnum = z.enum([
  'Administrative-Area',
  'Attack-Pattern',
  'Campaign',
  'Channel',
  'City',
  'Country',
  'Course-Of-Action',
  'Data-Component',
  'Data-Source',
  'Event',
  'Feedback',
  'Grouping',
  'Incident',
  'Case-Incident',
  'Indicator',
  'Individual',
  'Infrastructure',
  'Intrusion-Set',
  'Language',
  'Malware',
  'Malware-Analysis',
  'Narrative',
  'Note',
  'Observed-Data',
  'Opinion',
  'Organization',
  'Position',
  'Region',
  'Report',
  'Stix-Cyber-Observable',
  'Case-Rfi',
  'Case-Rft',
  'Sector',
  'System',
  'Task',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Tool',
  'Vulnerability',
]);

// Useful filters details

const RegardingOfRelationshipTypeItem = z.object({
  key: z.literal('relationship_type')
    .describe("The key of a 'regardingOf' relationship type filter, always 'relationship_type'."),
  values: z.array(RelationshipTypeEnum)
    .describe('A list of relationship type filter values.'),
});

const RegardingOfEntityNameItem = z.object({
  key: z.literal('id')
    .describe("The key of a 'regardingOf' entity name filter, always 'id'."),
  values: z.array(z.string())
    .describe('A list of entity name filter values.'),
});

const RegardingOfFilterItem = z.object({
  key: z.literal('regardingOf')
    .describe("The key of the 'regardingOf' filter, always 'regardingOf'."),
  values: z.array(z.union([RegardingOfEntityNameItem, RegardingOfRelationshipTypeItem]))
    .describe('A list of entity name or relationship type filter values.'),
  operator: z.literal('eq')
    .describe("The logic operator used for the 'regardingOf' filter, always 'eq'."),
  mode: z.literal('or')
    .describe("The combination mode used between the 'regardingOf' filter values, always 'or'."),
}).describe('A filter used to further refine entity filtering based on associated entities and/or relationships.');

const EntityTypeFilterItem = z.object({
  key: z.literal('entity_type')
    .describe("The key of the entity type filter, always 'entity_type'."),
  values: z.array(EntityTypeEnum)
    .describe('A list of entity type filter values.'),
  operator: z.literal('eq')
    .describe("The logic operator used for the entity type filter, always 'eq'."),
  mode: z.literal('or')
    .describe("The combination mode used between the entity type filter values, always 'or'."),
}).describe('A filter used to filter entities by their type as defined by the STIX standard.');

const ObjectAssigneeFilterItem = z.object({
  key: z.literal('objectAssignee')
    .describe("The key of the assignee filter, always 'objectAssignee'."),
  values: z.array(z.string())
    .describe('A list of assignees.'),
  operator: z.literal('eq')
    .describe("The logic operator used for the assignee filter, always 'eq'."),
  mode: z.literal('or')
    .describe("The combination mode between the assignee filter values, always 'or'."),
}).describe('A filter used to filter entities by the name of their assignees.');

const GenericFilterItem = z.object({
  key: FilterTypeEnum
    .describe('The key of the filter.'),
  values: z.array(z.string())
    .describe('A list of filter values.'),
  operator: z.literal('eq')
    .describe("The logic operator used for the filter, always 'eq'."),
  mode: z.literal('or')
    .describe("The combination mode between the filter values, always 'or'."),
});

export const OpenCTIFiltersOutput = z.object({
  filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, GenericFilterItem]))
    .describe('The list of filters'),
  mode: z.literal('and')
    .describe("The combination mode between the filters, always 'and'."),
  filterGroups: z.array(z.any()).default([]),
});

// // zod enums
// const FilterModeEnum = z.nativeEnum(FilterMode);
// const FilterOperatorEnum = z.nativeEnum(FilterOperator);

// TODO: To be used later
// const FilterSchema = z.object({
//   key: FilterTypeEnum
//     .describe('The key of the filter.'), // z.array(z.string()), // TODO how to validate key (generateFilterKeysSchema)
//   mode: FilterModeEnum.optional(),
//   operator: FilterOperatorEnum.optional(),
//   values: z.array(z.any()),
// });

// const FilterGroupSchema: z.ZodType<any> = z.lazy(() => z.object({
//   filterGroups: z.array(FilterGroupSchema),
//   filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, FilterSchema])),
//   mode: FilterModeEnum,
// }));

// examples

const jsonFewShotExamples: { _comment: string, input: string, output: unknown }[] = [
  {
    _comment: 'I/ Identification of threat actors by TTP ID (T1082 technique)',
    input: "Who's is behind this T1082?",
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'T1082'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'I/ Identification of threat actors by report or incident',
    input: 'Who are the threats in the PolarEdge ORB report?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'PolarEdge ORB report'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Intrusion-Set',
            'Threat-Actor-Group',
            'Threat-Actor-Individual'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'II/ Targeting and Potential Victims by Relationship (targets)',
    input: 'Which risks are most likely to affect me?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: [
                'targets'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'II/ Targeting and Potential Victims by ID (e.g., Malicious IP)',
    input: 'Which victims and industry sectors are being affected by 134.175.104.84?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: [
                'targets'
              ]
            },
            {
              key: 'id',
              values: [
                '134.175.104.84'
              ]
            }
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'III/ Relations and Behaviors - Tactics (uses)',
    input: 'How would Cyber Av3ngers carry out an attack on me?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'Cyber Av3ngers'
              ]
            },
            {
              key: 'relationship_type',
              values: [
                'uses'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Attack-Pattern'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (uses)',
    input: 'Can you list the malware used by MustardMan?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'MustardMan'
              ]
            },
            {
              key: 'relationship_type',
              values: [
                'uses'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Malware'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (without relationship)',
    input: 'Can you list the IOCs linked to APT-C-00 Ocean Lotus?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'APT-C-00  Ocean Lotus'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Indicator'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'IV/ Malware and IOCs Linked to an Actor (related-to)',
    input: "Does the file named 'example_file' have any associations with known threat actors or cyber threats?",
    output: {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        },
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: [
                'related-to'
              ]
            },
            {
              key: 'id',
              values: [
                'example_file'
              ]
            }
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'V/ Intelligence Reports and Incidents - Creators or Assignees (creator_id)',
    input: 'What intelligence reports have been released by the Cambridge Group of Clubs?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'creator_id',
          operator: 'eq',
          values: [
            'Cambridge Group of Clubs'
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Report'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'V/ Intelligence Reports and Incidents - Creators or Assignees (objectAssignee)',
    input: 'Can you list all cybersecurity incidents assigned to John Doe?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Incident'
          ],
          mode: 'or'
        },
        {
          key: 'objectAssignee',
          operator: 'eq',
          values: [
            'John Doe'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'VI/ Diversification of Entities (here Vulnerabilities related to a TTP) (Attack-Pattern, Intrusion-Set, Malware, Indicator, Incident, Threat-Actor, Campaign (ny), Course-of-Action (ny), Tool (ny), Vulnerability, Report)',
    input: 'What vulnerabilities are associated with T1497?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            { key: 'id', values: ['T1497'] }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: ['Vulnerability'],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'VII/ Diversity of Relationships (targets - Victims or industry sectors targeted by an IP) (uses, targets, related-to, located-at)',
    input: 'Which victims and industry sectors are targeted by 134.175.104.84?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            { key: 'relationship_type', values: ['targets'] },
            { key: 'id', values: ['134.175.104.84'] }
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'VII/ Diversity of Relationships (located-at - Geolocation of threat actors) (uses, targets, related-to, located-at, mitigates(ny), indicates(ny), compromises(ny))',
    input: 'Which actors are located in Russia?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            { key: 'relationship_type', values: ['located-at'] },
            { key: 'id', values: ['Russia'] }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'VIII/ General and Non-CTI Questions (returns empty filters)',
    input: 'What is the impact of quantum computing on encryption?',
    output: { mode: 'and', filters: [], filterGroups: [] }
  },
  {
    _comment: "VIII/ Grammatical and Linguistic Complexity (should return nothing as it's non-CTI)",
    input: 'The sun, a radiant beacon in the sky, spread its golden warmth across the horizon, igniting the dawn with an explosion of brilliant color.',
    output: { mode: 'and', filters: [], filterGroups: [] }
  },
  {
    _comment: 'IX/ Complex Questions and Linguistic Complexity: Passive Voice - Conditional Statements - TODO: Support conditional logic',
    input: 'If T1497 was involved, who would be responsible?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'T1497'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'IX/ Complex Questions and Linguistic Complexity: Indirect Questions - TODO: Interpret indirect questions',
    input: 'I wonder who is behind T1497.',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'T1497'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'IX/ Complex Questions and Linguistic Complexity: Logical Operators - TODO: Improve handling of logical operators (AND, OR)',
    input: 'Who uses either T1497 or T1082?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'T1497'
              ]
            },
            {
              key: 'id',
              values: [
                'T1082'
              ]
            },
            {
              key: 'relationship_type',
              values: [
                'uses'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
            'Intrusion-Set'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  },
  {
    _comment: 'Prevent other key values.',
    input: 'What are the vulnerabilities related with paradise?',
    output: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'paradise'
              ]
            }
          ],
          mode: 'or'
        },
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Vulnerability'
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    }
  }
];

const examples = jsonFewShotExamples.map((item) => ({
  input: item.input,
  output: JSON.stringify(OpenCTIFiltersOutput.safeParse(item.output)).replace(/"/g, "'")
}));

const examplePrompt = ChatPromptTemplate.fromMessages([
  ['human', '{input}'],
  ['ai', '{output}'],
]);

// prompts

const fewShotPrompt = new FewShotChatMessagePromptTemplate({
  examplePrompt,
  examples,
  inputVariables: [],
});

const systemPrompt = `You are an expert in cybersecurity and OpenCTI query filters. 
    Your task is to extract OpenCTI filters from a given user input,
    which will be used to search for specific entities in the OpenCTI database.

    If the user input is not related to Cyber Threat Intelligence (CTI),
    return: {{"mode":"and","filters":[],"filterGroups":[]}}

    Output the result as valid JSON (strictly matching our FilterGroup schema).
    Do not add any extra text outside the JSON object.
  `;

export const NLQPromptTemplate = ChatPromptTemplate.fromMessages([
  ['system', systemPrompt],
  fewShotPrompt as unknown as ChatPromptTemplate,
  ['human', '{text}'],
]);
