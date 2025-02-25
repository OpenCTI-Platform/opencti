import { z } from 'zod';
import { ChatPromptTemplate, type Example, FewShotChatMessagePromptTemplate } from '@langchain/core/prompts';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { emptyFilterGroup } from '../../utils/filtering/filtering-utils';

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

// TODO not used?
// export const OpenCTIFiltersOutput = z.object({
//   filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, GenericFilterItem]))
//     .describe('The list of filters'),
//   mode: z.literal('and')
//     .describe("The combination mode between the filters, always 'and'."),
//   filterGroups: z.array(z.any()).default([]),
// });

// zod enums
const FilterModeEnum = z.nativeEnum(FilterMode);
const FilterOperatorEnum = z.nativeEnum(FilterOperator);

const FilterSchema = z.object({
  key: FilterTypeEnum
    .describe('The key of the filter.'), // z.array(z.string()), // TODO how to validate key (generateFilterKeysSchema)
  mode: FilterModeEnum.optional(),
  operator: FilterOperatorEnum.optional(),
  values: z.array(z.any()),
});

const FilterGroupSchema: z.ZodType<any> = z.lazy(() => z.object({
  filterGroups: z.array(FilterGroupSchema),
  filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, FilterSchema])),
  mode: FilterModeEnum,
}));

// examples

const examples: Example[] = [
  {
    input: "Who's is behind this T1497?",
    output: JSON.stringify({
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
    })
  },
  {
    input: 'Which threats actors are invovled with T1497?',
    output: JSON.stringify({
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
    })
  },
  {
    input: 'T1497に関与している脅威アクターは誰ですか？',
    output: JSON.stringify({
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
    })
  },
  {
    input: 'Google TAG COLDRIVER 2024年1月のレポートに含まれている脅威アクターは誰ですか？',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'Google TAG COLDRIVER January 2024'
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
    })
  },
  {
    input: 'Who are the actors responsible for T1497 attack?',
    output: JSON.stringify({
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
    })
  },
  {
    input: 'Which threats are most likely to target me?',
    output: JSON.stringify({
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
    })
  },
  {
    input: 'Agendaによって標的にされた被害者とその業界セクターは何ですか？',
    output: JSON.stringify({
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
                'Agenda'
              ]
            }
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    })
  },
  {
    input: 'If Russian cybercrime group attacks me, how will they do?',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'Russian cybercrime group'
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
    })
  },
  {
    input: 'ロシアのサイバー犯罪グループが私を攻撃する場合、どのように行いますか？',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'Russian cybercrime group'
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
    })
  },
  {
    input: 'APT28が使用したマルウェアのリストを教えてください。',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'APT28'
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
    })
  },
  {
    input: 'APT-C-01 (Poison Ivy)に関連するIOCのリストを教えてください。',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'id',
              values: [
                'APT-C-01 (Poison Ivy)'
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
    })
  },
  {
    input: "Does the file named 'example_file' have any associations with known threat actors or cyber threats?",
    output: JSON.stringify({
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
    })
  },
  {
    input: 'Has there been any historical involvement of XYZ in known cybersecurity incidents?',
    output: JSON.stringify({
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
                'XYZ'
              ]
            }
          ],
          mode: 'or'
        }
      ],
      filterGroups: []
    })
  },
  {
    input: 'List all intelligence reports released by Recorded Future.',
    output: JSON.stringify({
      mode: 'and',
      filters: [
        {
          key: 'creator_id',
          operator: 'eq',
          values: [
            'Recorded Future'
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
    })
  },
  {
    input: 'List all cybersecurity incidents assigned to John Doe.',
    output: JSON.stringify({
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
    })
  },
  {
    input: 'The sun, a radiant beacon in the sky, spread its golden warmth across the horizon, igniting the dawn with an explosion of brilliant color.',
    output: JSON.stringify(emptyFilterGroup),
  }
];

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
  fewShotPrompt,
  ['human', '{text}'],
]);
