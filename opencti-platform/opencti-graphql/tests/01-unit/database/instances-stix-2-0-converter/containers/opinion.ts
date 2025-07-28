import type { StoreEntity } from '../../../../../src/types/store';

export const OPINION_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  sort: [
    1750952183726
  ],
  opinion: 'agree',
  explanation: 'my opinion',
  confidence: 75,
  created: '2025-06-26T15:36:22.864Z',
  entity_type: 'Opinion',
  internal_id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  standard_id: 'opinion--0fe325be-7171-5696-a922-c9d15685c495',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T15:36:23.726Z',
  updated_at: '2025-06-26T15:37:27.254Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T15:37:27.254Z',
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object',
    'Container'
  ],
  i_attributes: [
    {
      updated_at: '2025-06-26T15:37:12.486Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 75,
      name: 'objectLabel'
    },
    {
      updated_at: '2025-06-26T15:37:27.208Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 75,
      name: 'objectOrganization'
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
        _id: '3f6a5599-5fcf-4189-a240-79bf5335494b',
        id: '3f6a5599-5fcf-4189-a240-79bf5335494b',
        sort: [
          'relationship-meta--3420fbc5-62f8-44ca-b9a9-90c05066022c'
        ],
        internal_id: '3f6a5599-5fcf-4189-a240-79bf5335494b',
        standard_id: 'relationship-meta--3420fbc5-62f8-44ca-b9a9-90c05066022c',
        entity_type: 'external-reference',
        base_type: 'RELATION',
        from: null,
        fromId: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
        fromRole: 'external-reference_from',
        fromName: 'agree',
        fromType: 'Opinion',
        source_ref: 'opinion--temporary',
        to: null,
        toId: '8d0bc3e7-f272-4e2e-b2b4-31515ed5e052',
        toRole: 'external-reference_to',
        toName: 'mitre-attack (G0096)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
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
      _id: 'a23a073c-2b6b-4850-8328-71e4015ee554',
      id: 'a23a073c-2b6b-4850-8328-71e4015ee554',
      sort: [
        'relationship-meta--3a1eb54e-ed51-436f-80c4-18d001763614'
      ],
      base_type: 'RELATION',
      internal_id: 'a23a073c-2b6b-4850-8328-71e4015ee554',
      standard_id: 'relationship-meta--3a1eb54e-ed51-436f-80c4-18d001763614',
      entity_type: 'created-by',
      from: null,
      fromId: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
      fromRole: 'created-by_from',
      fromName: 'agree',
      fromType: 'Opinion',
      source_ref: 'opinion--temporary',
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
    'b9aca079-0a66-4efd-a481-71b1ce745a3a'
  ],
  objects: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
      id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
      sort: [
        1750951974228
      ],
      attribute_abstract: 'this is a new note',
      content: 'with description:',
      note_types: [
        'analysis'
      ],
      likelihood: 50,
      confidence: 100,
      created: '2025-06-26T15:32:23.000Z',
      entity_type: 'Note',
      internal_id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
      standard_id: 'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [],
      created_at: '2025-06-26T15:32:54.228Z',
      updated_at: '2025-06-30T16:18:03.687Z',
      revoked: false,
      lang: 'en',
      modified: '2025-06-30T16:18:03.687Z',
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
          id: 'import/Note/b9aca079-0a66-4efd-a481-71b1ce745a3a/ipv4_example.json',
          name: 'ipv4_example.json',
          version: '2025-06-26T15:32:54.229Z',
          mime_type: 'application/json',
          file_markings: [
            '2cc876e4-ae90-497b-a4ae-16c762f0d03f'
          ]
        }
      ],
      i_attributes: [
        {
          updated_at: '2025-06-26T15:33:01.949Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'objects'
        },
        {
          updated_at: '2025-06-26T15:33:21.427Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'content'
        },
        {
          updated_at: '2025-06-26T15:33:21.427Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'standard_id'
        },
        {
          updated_at: '2025-06-26T15:36:24.277Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'opinions_metrics'
        },
        {
          updated_at: '2025-06-30T16:18:03.565Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'createdBy'
        }
      ],
      opinions_metrics: {
        total: 1,
        min: 4,
        max: 4,
        mean: 4
      },
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '98c4d77b-35c2-41b4-b3a6-08c4ac274dfc',
        id: '98c4d77b-35c2-41b4-b3a6-08c4ac274dfc',
        sort: [
          'relationship-meta--77e27e1d-f6c2-4124-aeb8-3a11e5144051'
        ],
        base_type: 'RELATION',
        internal_id: '98c4d77b-35c2-41b4-b3a6-08c4ac274dfc',
        standard_id: 'relationship-meta--77e27e1d-f6c2-4124-aeb8-3a11e5144051',
        entity_type: 'object',
        from: null,
        fromId: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
        fromRole: 'object_from',
        fromName: 'agree',
        fromType: 'Opinion',
        source_ref: 'opinion--temporary',
        to: null,
        toId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
        toRole: 'object_to',
        toName: 'this is a new note',
        toType: 'Note',
        target_ref: 'note--temporary',
        relationship_type: 'object'
      }
    }
  ],
  granted: [
    'c2d8a20f-879a-4d22-b4ad-b850c757eb75'
  ],
  objectOrganization: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: 'c2d8a20f-879a-4d22-b4ad-b850c757eb75',
      id: 'c2d8a20f-879a-4d22-b4ad-b850c757eb75',
      sort: [
        1750324075757
      ],
      identity_class: 'organization',
      name: 'Filigran',
      description: '',
      confidence: 100,
      entity_type: 'Organization',
      internal_id: 'c2d8a20f-879a-4d22-b4ad-b850c757eb75',
      standard_id: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [],
      created_at: '2025-06-19T09:07:55.757Z',
      updated_at: '2025-06-19T09:07:55.757Z',
      revoked: false,
      lang: 'en',
      created: '2025-06-19T09:07:55.757Z',
      modified: '2025-06-19T09:07:55.757Z',
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
        _id: '456621af-0edd-4fc2-b52d-3ca99cb0982b',
        id: '456621af-0edd-4fc2-b52d-3ca99cb0982b',
        sort: [
          'relationship-meta--eda5f930-03b1-46b7-88c5-f531418cae2b'
        ],
        base_type: 'RELATION',
        internal_id: '456621af-0edd-4fc2-b52d-3ca99cb0982b',
        standard_id: 'relationship-meta--eda5f930-03b1-46b7-88c5-f531418cae2b',
        entity_type: 'granted',
        from: null,
        fromId: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
        fromRole: 'granted_from',
        fromName: 'agree',
        fromType: 'Opinion',
        source_ref: 'opinion--temporary',
        to: null,
        toId: 'c2d8a20f-879a-4d22-b4ad-b850c757eb75',
        toRole: 'granted_to',
        toName: 'Filigran',
        toType: 'Organization',
        target_ref: 'identity--temporary',
        relationship_type: 'granted'
      }
    }
  ],
  'object-label': [
    '2fd7f18f-9ecc-420e-9a85-8ad49789f4a6'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '2fd7f18f-9ecc-420e-9a85-8ad49789f4a6',
      id: '2fd7f18f-9ecc-420e-9a85-8ad49789f4a6',
      sort: [
        1749548087702
      ],
      x_opencti_stix_ids: [],
      value: 'opinion',
      color: '#82b3ed',
      confidence: 100,
      entity_type: 'Label',
      internal_id: '2fd7f18f-9ecc-420e-9a85-8ad49789f4a6',
      standard_id: 'label--66cc3435-328c-5b6b-9a96-1f3bdfb23067',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:34:47.702Z',
      updated_at: '2025-06-10T09:34:47.702Z',
      created: '2025-06-10T09:34:47.702Z',
      modified: '2025-06-10T09:34:47.702Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '392f75eb-e708-4417-b584-611dfca11569',
        id: '392f75eb-e708-4417-b584-611dfca11569',
        sort: [
          'relationship-meta--f3db32f0-c734-4e95-8e99-f70481a523d2'
        ],
        base_type: 'RELATION',
        internal_id: '392f75eb-e708-4417-b584-611dfca11569',
        standard_id: 'relationship-meta--f3db32f0-c734-4e95-8e99-f70481a523d2',
        entity_type: 'object-label',
        from: null,
        fromId: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
        fromRole: 'object-label_from',
        fromName: 'agree',
        fromType: 'Opinion',
        source_ref: 'opinion--temporary',
        to: null,
        toId: '2fd7f18f-9ecc-420e-9a85-8ad49789f4a6',
        toRole: 'object-label_to',
        toName: 'opinion',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreEntity;

export const EXPECTED_OPINION = {
  id: 'opinion--0fe325be-7171-5696-a922-c9d15685c495',
  spec_version: '2.0',
  revoked: false,
  confidence: 75,
  created: '2025-06-26T15:36:22.864Z',
  modified: '2025-06-26T15:37:27.254Z',
  explanation: 'my opinion',
  opinion: 'agree',
  labels: [
    'opinion'
  ],
  external_references: [
    {
      source_name: 'mitre-attack',
      url: 'https://attack.mitre.org/groups/G0096',
      external_id: 'G0096'
    }
  ],
  x_opencti_id: '2a2d3e3e-a767-4184-aca1-a11e1d557d05',
  x_opencti_type: 'Opinion',
  type: 'opinion',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_refs: [
    'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8'
  ],
  x_opencti_granted_refs: [
    'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  ],
  x_opencti_files: [],
  object_marking_refs: [],
};
