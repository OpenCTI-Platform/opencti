import type { StoreEntity } from '../../../../../src/types/store';

export const OBSERVED_DATA_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '9653626d-54c7-433b-beca-ee1dee226125',
  id: '9653626d-54c7-433b-beca-ee1dee226125',
  sort: [
    1750951410704
  ],
  first_observed: '2025-06-18T22:00:00.000Z',
  last_observed: '2025-06-27T22:00:00.000Z',
  number_observed: 1,
  confidence: 94,
  entity_type: 'Observed-Data',
  internal_id: '9653626d-54c7-433b-beca-ee1dee226125',
  standard_id: 'observed-data--a9ed3299-df09-5bc6-bd5f-0831d75114ae',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T15:23:30.704Z',
  updated_at: '2025-06-26T15:29:37.100Z',
  revoked: false,
  lang: 'en',
  created: '2025-06-26T15:23:30.704Z',
  modified: '2025-06-26T15:29:37.100Z',
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
      id: 'import/Observed-Data/9653626d-54c7-433b-beca-ee1dee226125/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T15:23:30.705Z',
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
      updated_at: '2025-06-26T15:23:58.536Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T15:29:37.101Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 94,
      name: 'confidence'
    }
  ],
  object: [
    '66b4b5de-f98d-4a76-92d6-929a9000d114',
    'c808561d-ed59-4d54-914a-5d090eceafd6'
  ],
  objects: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '66b4b5de-f98d-4a76-92d6-929a9000d114',
      id: '66b4b5de-f98d-4a76-92d6-929a9000d114',
      sort: [
        1749547859691
      ],
      x_opencti_stix_ids: [
        'campaign--721976f9-56d7-4749-8c69-b3ac7c315f05'
      ],
      name: 'menuPass',
      description: 'The threat actor behind menuPass prefers to target U.S. and foreign defense contractors.',
      aliases: null,
      revoked: false,
      lang: 'en',
      confidence: 100,
      first_seen: '2009-12-14T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
      objective: null,
      created: '2015-05-15T09:12:16.432Z',
      modified: '2015-05-15T09:12:16.432Z',
      x_opencti_workflow_id: null,
      entity_type: 'Campaign',
      internal_id: '66b4b5de-f98d-4a76-92d6-929a9000d114',
      standard_id: 'campaign--737733a0-2cb5-5981-9814-53c0e3fbd9e9',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:30:59.691Z',
      updated_at: '2025-06-10T09:30:59.691Z',
      i_aliases_ids: [],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object'
      ],
      draft_ids: [
        '2c0ff00c-f892-4f22-b863-58de30313461'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '6741affa-a82f-4af4-90c6-64cff97fccee',
        id: '6741affa-a82f-4af4-90c6-64cff97fccee',
        sort: [
          'relationship-meta--27c19729-e0de-4619-ad7a-51cd25a5e0dd'
        ],
        base_type: 'RELATION',
        internal_id: '6741affa-a82f-4af4-90c6-64cff97fccee',
        standard_id: 'relationship-meta--27c19729-e0de-4619-ad7a-51cd25a5e0dd',
        entity_type: 'object',
        from: null,
        fromId: '9653626d-54c7-433b-beca-ee1dee226125',
        fromRole: 'object_from',
        fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
        fromType: 'Observed-Data',
        source_ref: 'observed-data--temporary',
        to: null,
        toId: '66b4b5de-f98d-4a76-92d6-929a9000d114',
        toRole: 'object_to',
        toName: 'menuPass',
        toType: 'Campaign',
        target_ref: 'campaign--temporary',
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
        _id: '66dd1766-4df7-4b99-ba37-6363a262d55f',
        id: '66dd1766-4df7-4b99-ba37-6363a262d55f',
        sort: [
          'relationship-meta--cba92725-4c14-4f08-929b-03ef38cf0b10'
        ],
        base_type: 'RELATION',
        internal_id: '66dd1766-4df7-4b99-ba37-6363a262d55f',
        standard_id: 'relationship-meta--cba92725-4c14-4f08-929b-03ef38cf0b10',
        entity_type: 'object',
        from: null,
        fromId: '9653626d-54c7-433b-beca-ee1dee226125',
        fromRole: 'object_from',
        fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
        fromType: 'Observed-Data',
        source_ref: 'observed-data--temporary',
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
        _id: '760e6082-4650-45f7-be01-5862262ad721',
        id: '760e6082-4650-45f7-be01-5862262ad721',
        sort: [
          'relationship-meta--3ce0615e-ef97-4680-947e-a2555cbeb8b8'
        ],
        base_type: 'RELATION',
        internal_id: '760e6082-4650-45f7-be01-5862262ad721',
        standard_id: 'relationship-meta--3ce0615e-ef97-4680-947e-a2555cbeb8b8',
        entity_type: 'external-reference',
        from: null,
        fromId: '9653626d-54c7-433b-beca-ee1dee226125',
        fromRole: 'external-reference_from',
        fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
        fromType: 'Observed-Data',
        source_ref: 'observed-data--temporary',
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
      _id: '510e8ef6-a40c-477f-8531-3775ac147467',
      id: '510e8ef6-a40c-477f-8531-3775ac147467',
      sort: [
        'relationship-meta--ba0d9f3f-f4cb-41ac-ac9b-bc7a5e3a57e7'
      ],
      base_type: 'RELATION',
      internal_id: '510e8ef6-a40c-477f-8531-3775ac147467',
      standard_id: 'relationship-meta--ba0d9f3f-f4cb-41ac-ac9b-bc7a5e3a57e7',
      entity_type: 'created-by',
      from: null,
      fromId: '9653626d-54c7-433b-beca-ee1dee226125',
      fromRole: 'created-by_from',
      fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
      fromType: 'Observed-Data',
      source_ref: 'observed-data--temporary',
      to: null,
      toId: '51bca270-ec82-4b04-bd0a-d78274c70d92',
      toRole: 'created-by_to',
      toName: 'John Doe',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
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
        _id: 'f5b12f5c-a75b-48b7-ab29-0eac4b77bc37',
        id: 'f5b12f5c-a75b-48b7-ab29-0eac4b77bc37',
        sort: [
          'relationship-meta--f1677424-59fd-4761-84b8-3b647d0edc09'
        ],
        base_type: 'RELATION',
        internal_id: 'f5b12f5c-a75b-48b7-ab29-0eac4b77bc37',
        standard_id: 'relationship-meta--f1677424-59fd-4761-84b8-3b647d0edc09',
        entity_type: 'object-marking',
        from: null,
        fromId: '9653626d-54c7-433b-beca-ee1dee226125',
        fromRole: 'object-marking_from',
        fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
        fromType: 'Observed-Data',
        source_ref: 'observed-data--temporary',
        to: null,
        toId: '2cc876e4-ae90-497b-a4ae-16c762f0d03f',
        toRole: 'object-marking_to',
        toName: 'PAP:CLEAR',
        toType: 'Marking-Definition',
        target_ref: 'marking-definition--temporary',
        relationship_type: 'object-marking'
      }
    }
  ],
  'object-label': [
    '1fd9eb0d-90ae-4cb7-8a0c-7d53fb9bbb3b'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '1fd9eb0d-90ae-4cb7-8a0c-7d53fb9bbb3b',
      id: '1fd9eb0d-90ae-4cb7-8a0c-7d53fb9bbb3b',
      sort: [
        1749547945672
      ],
      x_opencti_stix_ids: [],
      value: 'campaign',
      color: '#1001a9',
      confidence: 100,
      entity_type: 'Label',
      internal_id: '1fd9eb0d-90ae-4cb7-8a0c-7d53fb9bbb3b',
      standard_id: 'label--0d0ca8b0-45b3-5390-a0eb-67246411729f',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:25.672Z',
      updated_at: '2025-06-10T09:32:25.672Z',
      created: '2025-06-10T09:32:25.672Z',
      modified: '2025-06-10T09:32:25.672Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'adfb1904-6b41-4209-ae85-e5fff8e30559',
        id: 'adfb1904-6b41-4209-ae85-e5fff8e30559',
        sort: [
          'relationship-meta--f7187359-946c-47c7-8396-5149fb1a2392'
        ],
        base_type: 'RELATION',
        internal_id: 'adfb1904-6b41-4209-ae85-e5fff8e30559',
        standard_id: 'relationship-meta--f7187359-946c-47c7-8396-5149fb1a2392',
        entity_type: 'object-label',
        from: null,
        fromId: '9653626d-54c7-433b-beca-ee1dee226125',
        fromRole: 'object-label_from',
        fromName: '2025-06-18T22:00:00.000Z - 2025-06-27T22:00:00.000Z',
        fromType: 'Observed-Data',
        source_ref: 'observed-data--temporary',
        to: null,
        toId: '1fd9eb0d-90ae-4cb7-8a0c-7d53fb9bbb3b',
        toRole: 'object-label_to',
        toName: 'campaign',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreEntity;

export const EXPECTED_OBSERVED_DATA = {
  id: 'observed-data--a9ed3299-df09-5bc6-bd5f-0831d75114ae',
  spec_version: '2.0',
  revoked: false,
  confidence: 94,
  created: '2025-06-26T15:23:30.704Z',
  modified: '2025-06-26T15:29:37.100Z',
  first_observed: '2025-06-18T22:00:00.000Z',
  last_observed: '2025-06-27T22:00:00.000Z',
  number_observed: 1,
  labels: [
    'campaign'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: '9653626d-54c7-433b-beca-ee1dee226125',
  x_opencti_type: 'Observed-Data',
  type: 'observed-data',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'campaign--737733a0-2cb5-5981-9814-53c0e3fbd9e9',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a'
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Observed-Data/9653626d-54c7-433b-beca-ee1dee226125/ipv4_example.json',
      version: '2025-06-26T15:23:30.705Z',
    },
  ],
  x_opencti_granted_refs: [],
};
