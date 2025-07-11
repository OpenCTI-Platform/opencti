import type { StoreEntityGrouping2 } from '../../../../../src/modules/grouping/grouping-types';

export const GROUPING_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '2076a71c-a480-424f-8058-cb5c798e4360',
  id: '2076a71c-a480-424f-8058-cb5c798e4360',
  sort: [
    1750949983780
  ],
  name: 'grouping STIX 2.0',
  description: 'description',
  content: '<p>some content : Paradise Ransomware</p>',
  context: 'malware-analysis',
  confidence: 100,
  entity_type: 'Grouping',
  internal_id: '2076a71c-a480-424f-8058-cb5c798e4360',
  standard_id: 'grouping--3f78a876-9216-5111-92d8-6871301f6e9e',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T14:59:43.780Z',
  updated_at: '2025-06-26T15:14:12.529Z',
  revoked: false,
  lang: 'en',
  created: '2025-06-26T14:59:43.780Z',
  modified: '2025-06-26T15:14:12.529Z',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object',
    'Container'
  ],
  x_opencti_files: [
    {
      id: 'import/Grouping/2076a71c-a480-424f-8058-cb5c798e4360/file_example (2).json',
      name: 'file_example (2).json',
      version: '2025-06-26T14:59:43.780Z',
      mime_type: 'application/json',
      file_markings: [
        '2cc876e4-ae90-497b-a4ae-16c762f0d03f'
      ],
      objectMarking: [
        {
          _index: 'opencti_stix_meta_objects-000001',
          _id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          sort: [
            1749546753947
          ],
          entity_type: 'Marking-Definition',
          internal_id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
          standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
          base_type: 'ENTITY'
        }
      ]
    }
  ],
  i_attributes: [
    {
      updated_at: '2025-06-26T15:00:34.104Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T15:00:27.922Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content'
    },
    {
      updated_at: '2025-06-26T15:00:34.701Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content_mapping'
    }
  ],
  content_mapping: 'eyJhcmFkaXNlIHJhbnNvbXdhcmUiOiJtYWx3YXJlLS0yMWM0NWRiZS01NGVjLTViYjctYjhjZC05ZjI3Y2M1MTg3MTQifQ',
  'object-label': [
    'd6d10328-9d53-4da8-af37-fb859cbbc693'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      sort: [
        1749547953634
      ],
      x_opencti_stix_ids: [],
      value: 'ryuk',
      color: '#1da735',
      confidence: 100,
      entity_type: 'Label',
      internal_id: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
      standard_id: 'label--66b4d95f-ba1a-54b3-b5a3-74c7fb93142b',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:33.634Z',
      updated_at: '2025-06-10T09:32:33.634Z',
      created: '2025-06-10T09:32:33.634Z',
      modified: '2025-06-10T09:32:33.634Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '27a66ec3-18a2-4127-9b33-9eb48bc48a6c',
        id: '27a66ec3-18a2-4127-9b33-9eb48bc48a6c',
        sort: [
          'relationship-meta--0c7719eb-fc66-4e91-9089-be46649a786b'
        ],
        base_type: 'RELATION',
        internal_id: '27a66ec3-18a2-4127-9b33-9eb48bc48a6c',
        standard_id: 'relationship-meta--0c7719eb-fc66-4e91-9089-be46649a786b',
        entity_type: 'object-label',
        from: null,
        fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
        fromRole: 'object-label_from',
        fromName: 'grouping STIX 2.0',
        fromType: 'Grouping',
        source_ref: 'grouping--temporary',
        to: null,
        toId: 'd6d10328-9d53-4da8-af37-fb859cbbc693',
        toRole: 'object-label_to',
        toName: 'ryuk',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ],
  'external-reference': [
    '746847b8-f5d0-4c82-a7a2-70649ac9b135'
  ],
  externalReferences: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      sort: [
        1749547864832
      ],
      x_opencti_stix_ids: [],
      source_name: 'capec',
      description: 'spear phishing',
      url: null,
      external_id: 'CAPEC-163',
      created: '2025-06-10T09:31:04.832Z',
      modified: '2025-06-10T09:31:04.832Z',
      confidence: 100,
      entity_type: 'External-Reference',
      internal_id: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
      standard_id: 'external-reference--4a67461d-68b8-5a27-996f-a8e30578cb56',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:31:04.832Z',
      updated_at: '2025-06-10T09:31:04.832Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'f4057aee-e4e0-4f91-b2ab-3bf9f319ab67',
        id: 'f4057aee-e4e0-4f91-b2ab-3bf9f319ab67',
        sort: [
          'relationship-meta--1dfbee6d-2276-4b17-b0fa-f85f79ed1e17'
        ],
        base_type: 'RELATION',
        internal_id: 'f4057aee-e4e0-4f91-b2ab-3bf9f319ab67',
        standard_id: 'relationship-meta--1dfbee6d-2276-4b17-b0fa-f85f79ed1e17',
        entity_type: 'external-reference',
        from: null,
        fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
        fromRole: 'external-reference_from',
        fromName: 'grouping STIX 2.0',
        fromType: 'Grouping',
        source_ref: 'grouping--temporary',
        to: null,
        toId: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
        toRole: 'external-reference_to',
        toName: 'capec (CAPEC-163)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ],
  'created-by': '51bca270-ec82-4b04-bd0a-d78274c70d92',
  createdBy: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '51bca270-ec82-4b04-bd0a-d78274c70d92',
    id: '51bca270-ec82-4b04-bd0a-d78274c70d92',
    sort: [
      1749547918224
    ],
    x_opencti_stix_ids: [
      'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f'
    ],
    name: 'John Doe',
    description: null,
    contact_information: null,
    roles: null,
    x_opencti_aliases: null,
    x_opencti_firstname: null,
    x_opencti_lastname: null,
    x_opencti_reliability: null,
    confidence: 100,
    revoked: false,
    lang: 'en',
    created: '2020-03-27T08:39:45.676Z',
    modified: '2025-06-10T09:31:58.237Z',
    x_opencti_workflow_id: null,
    identity_class: 'individual',
    entity_type: 'Individual',
    internal_id: '51bca270-ec82-4b04-bd0a-d78274c70d92',
    standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    created_at: '2025-06-10T09:31:58.224Z',
    updated_at: '2025-06-10T09:31:58.237Z',
    i_aliases_ids: [],
    base_type: 'ENTITY',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Core-Object',
      'Stix-Domain-Object',
      'Identity'
    ],
    i_relation: {
      _index: 'opencti_stix_meta_relationships-000001',
      _id: '543e9da6-d709-4fab-83df-4eeacfa323ab',
      id: '543e9da6-d709-4fab-83df-4eeacfa323ab',
      sort: [
        'relationship-meta--3802fa95-7965-42d8-a56e-7de105a92990'
      ],
      base_type: 'RELATION',
      internal_id: '543e9da6-d709-4fab-83df-4eeacfa323ab',
      standard_id: 'relationship-meta--3802fa95-7965-42d8-a56e-7de105a92990',
      entity_type: 'created-by',
      from: null,
      fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
      fromRole: 'created-by_from',
      fromName: 'grouping STIX 2.0',
      fromType: 'Grouping',
      source_ref: 'grouping--temporary',
      to: null,
      toId: '51bca270-ec82-4b04-bd0a-d78274c70d92',
      toRole: 'created-by_to',
      toName: 'John Doe',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
  object: [
    'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
    'c808561d-ed59-4d54-914a-5d090eceafd6'
  ],
  objects: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      sort: [
        1749547881666
      ],
      x_opencti_stix_ids: [
        'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c'
      ],
      name: 'Paradise Ransomware',
      description: 'MalwareHunterTeam discovered a new Paradise Ransomware variant that uses the extension _V.0.0.0.1{paradise@all-ransomware.info}.prt and drops a ransom note named PARADISE_README_paradise@all-ransomware.info.txt.',
      malware_types: null,
      aliases: null,
      is_family: false,
      first_seen: '1970-01-01T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
      architecture_execution_envs: null,
      implementation_languages: null,
      capabilities: null,
      confidence: 100,
      revoked: false,
      lang: 'en',
      created: '2019-09-30T16:38:26.000Z',
      modified: '2025-06-10T09:34:55.065Z',
      x_opencti_workflow_id: null,
      entity_type: 'Malware',
      internal_id: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
      standard_id: 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:31:21.666Z',
      updated_at: '2025-06-10T09:34:55.065Z',
      i_aliases_ids: [],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object'
      ],
      opinions_metrics: {
        total: 1,
        min: 5,
        max: 5,
        mean: 5
      },
      i_attributes: [
        {
          updated_at: '2025-06-10T09:34:55.065Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'opinions_metrics'
        }
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '06eaad2e-8b26-4468-b266-dd5e88fcfcdd',
        id: '06eaad2e-8b26-4468-b266-dd5e88fcfcdd',
        sort: [
          'relationship-meta--672008b1-242f-4248-877e-5223d06eb000'
        ],
        base_type: 'RELATION',
        internal_id: '06eaad2e-8b26-4468-b266-dd5e88fcfcdd',
        standard_id: 'relationship-meta--672008b1-242f-4248-877e-5223d06eb000',
        entity_type: 'object',
        from: null,
        fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
        fromRole: 'object_from',
        fromName: 'grouping STIX 2.0',
        fromType: 'Grouping',
        source_ref: 'grouping--temporary',
        to: null,
        toId: 'dce63edb-533e-4ca5-9d00-f88c51aff6fb',
        toRole: 'object_to',
        toName: 'Paradise Ransomware',
        toType: 'Malware',
        target_ref: 'malware--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_cyber_observables-000001',
      _id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      sort: [
        1749548017333
      ],
      x_opencti_score: 50,
      x_opencti_description: 'Basic credential',
      value: 'azerty',
      confidence: 100,
      entity_type: 'Credential',
      internal_id: 'c808561d-ed59-4d54-914a-5d090eceafd6',
      standard_id: 'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [
        'credential--8e0a834a-c233-5c50-8186-adde10a69f02'
      ],
      created_at: '2025-06-10T09:33:37.333Z',
      updated_at: '2025-06-10T09:33:37.345Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Cyber-Observable'
      ],
      modified: '2025-06-10T09:33:37.345Z',
      draft_ids: [
        '2c0ff00c-f892-4f22-b863-58de30313461'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '0ae73426-50c1-45c3-b726-8b213f2b32f5',
        id: '0ae73426-50c1-45c3-b726-8b213f2b32f5',
        sort: [
          'relationship-meta--c2ec1ed8-0228-49e2-885a-e9061c4c263f'
        ],
        base_type: 'RELATION',
        internal_id: '0ae73426-50c1-45c3-b726-8b213f2b32f5',
        standard_id: 'relationship-meta--c2ec1ed8-0228-49e2-885a-e9061c4c263f',
        entity_type: 'object',
        from: null,
        fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
        fromRole: 'object_from',
        fromName: 'grouping STIX 2.0',
        fromType: 'Grouping',
        source_ref: 'grouping--temporary',
        to: null,
        toId: 'c808561d-ed59-4d54-914a-5d090eceafd6',
        toRole: 'object_to',
        toName: 'azerty',
        toType: 'Credential',
        target_ref: 'credential--temporary',
        relationship_type: 'object'
      }
    }
  ],
  'object-marking': [
    '2cc876e4-ae90-497b-a4ae-16c762f0d03f'
  ],
  objectMarking: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      sort: [
        1749546753947
      ],
      definition_type: 'PAP',
      definition: 'PAP:CLEAR',
      x_opencti_color: '#ffffff',
      x_opencti_order: 1,
      confidence: 100,
      entity_type: 'Marking-Definition',
      internal_id: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
      standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      creator_id: [
        '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
      ],
      x_opencti_stix_ids: [],
      created_at: '2025-06-10T09:12:33.947Z',
      updated_at: '2025-06-10T09:12:33.947Z',
      created: '2025-06-10T09:12:33.947Z',
      modified: '2025-06-10T09:12:33.947Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '732f9d50-43e9-47f1-bf57-307b7836014c',
        id: '732f9d50-43e9-47f1-bf57-307b7836014c',
        sort: [
          'relationship-meta--daae0085-9694-42b9-bfc8-8ede9cd21e59'
        ],
        base_type: 'RELATION',
        internal_id: '732f9d50-43e9-47f1-bf57-307b7836014c',
        standard_id: 'relationship-meta--daae0085-9694-42b9-bfc8-8ede9cd21e59',
        entity_type: 'object-marking',
        from: null,
        fromId: '2076a71c-a480-424f-8058-cb5c798e4360',
        fromRole: 'object-marking_from',
        fromName: 'grouping STIX 2.0',
        fromType: 'Grouping',
        source_ref: 'grouping--temporary',
        to: null,
        toId: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
        toRole: 'object-marking_to',
        toName: 'PAP:CLEAR',
        toType: 'Marking-Definition',
        target_ref: 'marking-definition--temporary',
        relationship_type: 'object-marking'
      }
    }
  ]
} as unknown as StoreEntityGrouping2;

export const EXPECTED_GROUPING = {
  id: 'grouping--3f78a876-9216-5111-92d8-6871301f6e9e',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T14:59:43.780Z',
  modified: '2025-06-26T15:14:12.529Z',
  name: 'grouping STIX 2.0',
  description: 'description',
  context: 'malware-analysis',
  labels: [
    'ryuk'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: '2076a71c-a480-424f-8058-cb5c798e4360',
  x_opencti_type: 'Grouping',
  type: 'grouping',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a'
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'file_example (2).json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Grouping/2076a71c-a480-424f-8058-cb5c798e4360/file_example (2).json',
      version: '2025-06-26T14:59:43.780Z',
    },
  ],
  x_opencti_granted_refs: [],
};
