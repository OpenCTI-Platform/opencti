import type { StoreEntity } from '../../../../../src/types/store';

export const NOTE_INSTANCE = {
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
  updated_at: '2025-06-26T15:33:21.426Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T15:33:21.426Z',
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
        _id: '13858342-1dbb-4aed-864e-bd5107a37144',
        id: '13858342-1dbb-4aed-864e-bd5107a37144',
        sort: [
          'relationship-meta--039c48f2-4de1-48e8-9ef9-f1c6481d7bc4'
        ],
        base_type: 'RELATION',
        internal_id: '13858342-1dbb-4aed-864e-bd5107a37144',
        standard_id: 'relationship-meta--039c48f2-4de1-48e8-9ef9-f1c6481d7bc4',
        entity_type: 'object-marking',
        from: null,
        fromId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
        fromRole: 'object-marking_from',
        fromName: 'this is a new note',
        fromType: 'Note',
        source_ref: 'note--temporary',
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
      _id: 'ca886242-e92e-44a9-8e1c-abbb37b7aaa7',
      id: 'ca886242-e92e-44a9-8e1c-abbb37b7aaa7',
      sort: [
        'relationship-meta--1466aa5f-7359-486e-a939-43b1a5891959'
      ],
      base_type: 'RELATION',
      internal_id: 'ca886242-e92e-44a9-8e1c-abbb37b7aaa7',
      standard_id: 'relationship-meta--1466aa5f-7359-486e-a939-43b1a5891959',
      entity_type: 'created-by',
      from: null,
      fromId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
      fromRole: 'created-by_from',
      fromName: 'this is a new note',
      fromType: 'Note',
      source_ref: 'note--temporary',
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
    '61d32033-aba5-4d84-9af2-8e1636daef06'
  ],
  objects: [
    {
      _index: 'opencti_stix_cyber_observables-000001',
      _id: '61d32033-aba5-4d84-9af2-8e1636daef06',
      id: '61d32033-aba5-4d84-9af2-8e1636daef06',
      sort: [
        1749558674505
      ],
      x_opencti_score: 50,
      x_opencti_description: null,
      value: 'domain.com',
      confidence: 100,
      entity_type: 'Domain-Name',
      internal_id: '61d32033-aba5-4d84-9af2-8e1636daef06',
      standard_id: 'domain-name--c9d852bc-ec1b-57c8-b013-32f0f402f7a8',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [],
      created_at: '2025-06-10T12:31:14.505Z',
      updated_at: '2025-06-10T12:31:14.505Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Cyber-Observable'
      ],
      draft_ids: [
        '2c0ff00c-f892-4f22-b863-58de30313461'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'ba51b9b5-4ba8-4115-9a48-aa48a2c3ee50',
        id: 'ba51b9b5-4ba8-4115-9a48-aa48a2c3ee50',
        sort: [
          'relationship-meta--6df0534b-649a-4fdd-8365-3d604fa3d1c4'
        ],
        base_type: 'RELATION',
        internal_id: 'ba51b9b5-4ba8-4115-9a48-aa48a2c3ee50',
        standard_id: 'relationship-meta--6df0534b-649a-4fdd-8365-3d604fa3d1c4',
        entity_type: 'object',
        from: null,
        fromId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
        fromRole: 'object_from',
        fromName: 'this is a new note',
        fromType: 'Note',
        source_ref: 'note--temporary',
        to: null,
        toId: '61d32033-aba5-4d84-9af2-8e1636daef06',
        toRole: 'object_to',
        toName: 'domain.com',
        toType: 'Domain-Name',
        target_ref: 'domain-name--temporary',
        relationship_type: 'object'
      }
    }
  ],
  'object-label': [
    'cac715a5-fac1-4e71-8379-2ab310195eb5'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'cac715a5-fac1-4e71-8379-2ab310195eb5',
      id: 'cac715a5-fac1-4e71-8379-2ab310195eb5',
      sort: [
        1749548015988
      ],
      x_opencti_stix_ids: [],
      value: 'note',
      color: '#f2af33',
      confidence: 100,
      entity_type: 'Label',
      internal_id: 'cac715a5-fac1-4e71-8379-2ab310195eb5',
      standard_id: 'label--1f9a882f-2465-575d-b2fe-891b613dc4e2',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:33:35.988Z',
      updated_at: '2025-06-10T09:33:35.988Z',
      created: '2025-06-10T09:33:35.988Z',
      modified: '2025-06-10T09:33:35.988Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '7b62201b-f118-4e4c-a1f9-5fafbc6853aa',
        id: '7b62201b-f118-4e4c-a1f9-5fafbc6853aa',
        sort: [
          'relationship-meta--8790c650-8323-408b-a390-5043bab58667'
        ],
        base_type: 'RELATION',
        internal_id: '7b62201b-f118-4e4c-a1f9-5fafbc6853aa',
        standard_id: 'relationship-meta--8790c650-8323-408b-a390-5043bab58667',
        entity_type: 'object-label',
        from: null,
        fromId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
        fromRole: 'object-label_from',
        fromName: 'this is a new note',
        fromType: 'Note',
        source_ref: 'note--temporary',
        to: null,
        toId: 'cac715a5-fac1-4e71-8379-2ab310195eb5',
        toRole: 'object-label_to',
        toName: 'note',
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
        _id: '6eb4426f-16bb-4c78-8dff-688e278e7ebd',
        id: '6eb4426f-16bb-4c78-8dff-688e278e7ebd',
        sort: [
          'relationship-meta--a137427b-2b66-4cd0-9ef9-051ba61e5f59'
        ],
        base_type: 'RELATION',
        internal_id: '6eb4426f-16bb-4c78-8dff-688e278e7ebd',
        standard_id: 'relationship-meta--a137427b-2b66-4cd0-9ef9-051ba61e5f59',
        entity_type: 'external-reference',
        from: null,
        fromId: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
        fromRole: 'external-reference_from',
        fromName: 'this is a new note',
        fromType: 'Note',
        source_ref: 'note--temporary',
        to: null,
        toId: '746847b8-f5d0-4c82-a7a2-70649ac9b135',
        toRole: 'external-reference_to',
        toName: 'capec (CAPEC-163)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ]
} as unknown as StoreEntity;

export const EXPECTED_NOTE = {
  id: 'note--2a80c942-1c85-5bb7-91d4-e92ed2b86fd8',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T15:32:23.000Z',
  modified: '2025-06-26T15:33:21.426Z',
  content: 'with description:',
  note_types: [
    'analysis'
  ],
  likelihood: 50,
  labels: [
    'note'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: 'b9aca079-0a66-4efd-a481-71b1ce745a3a',
  x_opencti_type: 'Note',
  type: 'note',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'domain-name--c9d852bc-ec1b-57c8-b013-32f0f402f7a8'
  ],
  abstract: 'this is a new note',
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Note/b9aca079-0a66-4efd-a481-71b1ce745a3a/ipv4_example.json',
      version: '2025-06-26T15:32:54.229Z',
    },
  ],
  x_opencti_granted_refs: [],
};
