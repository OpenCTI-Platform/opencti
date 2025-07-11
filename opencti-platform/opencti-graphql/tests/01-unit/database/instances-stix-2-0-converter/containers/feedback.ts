import type { StoreEntityStix2Feedback } from '../../../../../src/modules/case/feedback/feedback-types';

export const FEEDBACK_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  sort: [
    1750953496638
  ],
  name: 'Feedback from admin@opencti.io',
  description: 'Feedback STIX 2.0',
  confidence: 93,
  rating: 3,
  created: '2025-06-26T15:58:16.208Z',
  entity_type: 'Feedback',
  internal_id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  standard_id: 'feedback--ce07ddc6-2377-576b-ace5-a4de6996e789',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T15:58:16.638Z',
  updated_at: '2025-06-26T16:04:50.126Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T16:04:50.126Z',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object',
    'Container',
    'Case'
  ],
  x_opencti_files: [
    {
      id: 'import/Feedback/5a194bd5-1fe1-4618-bfa0-48b15eb590b4/file_example (2).json',
      name: 'file_example (2).json',
      version: '2025-06-26T15:58:16.639Z',
      mime_type: 'application/json',
      file_markings: []
    }
  ],
  i_attributes: [
    {
      updated_at: '2025-06-26T15:58:43.662Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T15:59:54.283Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 93,
      name: 'confidence'
    },
    {
      updated_at: '2025-06-26T16:04:50.126Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 93,
      name: 'rating'
    }
  ],
  'created-by': '0097209b-e5d7-43f2-b901-cf665df73f6b',
  createdBy: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    sort: [
      1749548300272
    ],
    name: 'admin',
    contact_information: 'admin@opencti.io',
    identity_class: 'individual',
    confidence: 100,
    entity_type: 'Individual',
    internal_id: '0097209b-e5d7-43f2-b901-cf665df73f6b',
    standard_id: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    x_opencti_stix_ids: [],
    created_at: '2025-06-10T09:38:20.272Z',
    updated_at: '2025-06-10T09:38:28.303Z',
    revoked: false,
    lang: 'en',
    created: '2025-06-10T09:38:20.272Z',
    modified: '2025-06-10T09:38:28.303Z',
    i_aliases_ids: [],
    base_type: 'ENTITY',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Core-Object',
      'Stix-Domain-Object',
      'Identity'
    ],
    x_opencti_firstname: 'Admin',
    x_opencti_lastname: 'OpenCTI',
    i_attributes: [
      {
        updated_at: '2025-06-10T09:38:28.303Z',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        confidence: 100,
        name: 'x_opencti_firstname'
      },
      {
        updated_at: '2025-06-10T09:38:28.303Z',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        confidence: 100,
        name: 'x_opencti_lastname'
      }
    ],
    i_relation: {
      _index: 'opencti_stix_meta_relationships-000001',
      _id: 'c262a695-5195-41cc-a3fc-ddb30a1e4356',
      id: 'c262a695-5195-41cc-a3fc-ddb30a1e4356',
      sort: [
        'relationship-meta--0c4fe342-c6d7-4f47-991b-4a34d1f41405'
      ],
      base_type: 'RELATION',
      internal_id: 'c262a695-5195-41cc-a3fc-ddb30a1e4356',
      standard_id: 'relationship-meta--0c4fe342-c6d7-4f47-991b-4a34d1f41405',
      entity_type: 'created-by',
      from: null,
      fromId: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
      fromRole: 'created-by_from',
      fromName: 'Feedback from admin@opencti.io',
      fromType: 'Feedback',
      source_ref: 'feedback--temporary',
      to: null,
      toId: '0097209b-e5d7-43f2-b901-cf665df73f6b',
      toRole: 'created-by_to',
      toName: 'admin',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
  object: [
    'c808561d-ed59-4d54-914a-5d090eceafd6'
  ],
  objects: [
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
        _id: '124a980d-c312-4f0a-a678-4a741dca06ce',
        id: '124a980d-c312-4f0a-a678-4a741dca06ce',
        sort: [
          'relationship-meta--2bbdf891-4c18-4bf1-a6b6-d270235a0300'
        ],
        base_type: 'RELATION',
        internal_id: '124a980d-c312-4f0a-a678-4a741dca06ce',
        standard_id: 'relationship-meta--2bbdf891-4c18-4bf1-a6b6-d270235a0300',
        entity_type: 'object',
        from: null,
        fromId: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
        fromRole: 'object_from',
        fromName: 'Feedback from admin@opencti.io',
        fromType: 'Feedback',
        source_ref: 'feedback--temporary',
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
        _id: '50700c7a-a79a-4c60-a083-f570ee248553',
        id: '50700c7a-a79a-4c60-a083-f570ee248553',
        sort: [
          'relationship-meta--446f21cb-7a21-44b5-bc47-fd4143c27b61'
        ],
        base_type: 'RELATION',
        internal_id: '50700c7a-a79a-4c60-a083-f570ee248553',
        standard_id: 'relationship-meta--446f21cb-7a21-44b5-bc47-fd4143c27b61',
        entity_type: 'object-label',
        from: null,
        fromId: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
        fromRole: 'object-label_from',
        fromName: 'Feedback from admin@opencti.io',
        fromType: 'Feedback',
        source_ref: 'feedback--temporary',
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
    '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052'
  ],
  externalReferences: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052',
      id: '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052',
      sort: [
        1749547998399
      ],
      x_opencti_stix_ids: [],
      source_name: 'mitre-attack',
      description: null,
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096',
      created: '2025-06-10T09:33:18.399Z',
      modified: '2025-06-10T09:33:18.399Z',
      confidence: 100,
      entity_type: 'External-Reference',
      internal_id: '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052',
      standard_id: 'external-reference--1aba42b8-d1a9-51cb-8bc4-aecc241055c8',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:33:18.399Z',
      updated_at: '2025-06-10T09:33:18.399Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'dc73c6b9-1ec3-4410-9443-e67b31bb601f',
        id: 'dc73c6b9-1ec3-4410-9443-e67b31bb601f',
        sort: [
          'relationship-meta--fdc9b79e-0e11-4774-9195-43bbac626a0f'
        ],
        internal_id: 'dc73c6b9-1ec3-4410-9443-e67b31bb601f',
        standard_id: 'relationship-meta--fdc9b79e-0e11-4774-9195-43bbac626a0f',
        entity_type: 'external-reference',
        base_type: 'RELATION',
        from: null,
        fromId: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
        fromRole: 'external-reference_from',
        fromName: 'Feedback from admin@opencti.io',
        fromType: 'Feedback',
        source_ref: 'feedback--temporary',
        to: null,
        toId: '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052',
        toRole: 'external-reference_to',
        toName: 'mitre-attack (G0096)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ]
} as unknown as StoreEntityStix2Feedback;

export const EXPECTED_FEEDBACK = {
  id: 'x-opencti-feedback--ce07ddc6-2377-576b-ace5-a4de6996e789',
  spec_version: '2.0',
  revoked: false,
  confidence: 93,
  created: '2025-06-26T15:58:16.208Z',
  modified: '2025-06-26T16:04:50.126Z',
  name: 'Feedback from admin@opencti.io',
  description: 'Feedback STIX 2.0',
  rating: 3,
  labels: [
    'ryuk'
  ],
  external_references: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096'
    }
  ],
  x_opencti_id: '5a194bd5-1fe1-4618-bfa0-48b15eb590b4',
  x_opencti_type: 'Feedback',
  type: 'x-opencti-feedback',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_refs: [
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a'
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'file_example (2).json',
      object_marking_refs: [],
      uri: '/storage/get/import/Feedback/5a194bd5-1fe1-4618-bfa0-48b15eb590b4/file_example (2).json',
      version: '2025-06-26T15:58:16.639Z',
    },
  ],
  object_marking_refs: [],
  x_opencti_granted_refs: [],
};
