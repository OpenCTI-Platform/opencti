import type { StoreEntityCaseIncident2 } from '../../../../../src/modules/case/case-incident/case-incident-types';

export const INCIDENT_RESPONSE_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  sort: [
    1750954012221
  ],
  name: 'IR STIX 2.0',
  severity: 'medium',
  priority: 'P2',
  description: 'description',
  content: '<p>some content</p>',
  confidence: 100,
  created: '2025-06-26T16:06:02.000Z',
  response_types: [
    'data-leak'
  ],
  entity_type: 'Case-Incident',
  internal_id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  standard_id: 'case-incident--0ed8c294-d99f-5155-a54b-7cc3044174c3',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T16:06:52.221Z',
  updated_at: '2025-06-26T16:06:52.288Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T16:06:52.288Z',
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
      id: 'import/Case-Incident/4c849ab0-81f2-457c-b837-bea76f4d4d15/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T16:06:52.222Z',
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
  'object-participant': [
    '0ff0750e-4d91-425d-b44c-b69269dead0b'
  ],
  objectParticipant: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      sort: [
        1750152527269
      ],
      user_email: 'marie.flores@filigran.io',
      name: 'marie',
      password: '$2a$10$GElYhi3IFp7bSu6jYNz/JO4tCVNWr6tVEXJXLr/npfbS.EYu/8YlC',
      firstname: '',
      lastname: '',
      description: '',
      account_status: 'Active',
      account_lock_after_date: null,
      user_confidence_level: null,
      api_token: 'dfd7ed5d-5374-4a2e-a088-4a4c0013ccd7',
      theme: 'default',
      language: 'auto',
      external: false,
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      confidence: 100,
      entity_type: 'User',
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-17T09:28:47.269Z',
      updated_at: '2025-06-17T09:28:47.332Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      modified: '2025-06-17T09:28:47.332Z',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'e0bcc714-dd54-4ea6-830a-1d0797e1d098',
        id: 'e0bcc714-dd54-4ea6-830a-1d0797e1d098',
        sort: [
          'relationship-meta--57cfb634-7e5c-41c8-b712-a2274dfdcb62'
        ],
        base_type: 'RELATION',
        internal_id: 'e0bcc714-dd54-4ea6-830a-1d0797e1d098',
        standard_id: 'relationship-meta--57cfb634-7e5c-41c8-b712-a2274dfdcb62',
        entity_type: 'object-participant',
        from: null,
        fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
        fromRole: 'object-participant_from',
        fromName: 'IR STUX 2.0',
        fromType: 'Case-Incident',
        source_ref: 'case-incident--temporary',
        to: null,
        toId: '0ff0750e-4d91-425d-b44c-b69269dead0b',
        toRole: 'object-participant_to',
        toName: 'marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-participant'
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
        _id: '083365d2-b26e-4106-99e5-ace5e8c26a27',
        id: '083365d2-b26e-4106-99e5-ace5e8c26a27',
        sort: [
          'relationship-meta--6833472e-7fac-4612-b778-5da0b46f719e'
        ],
        base_type: 'RELATION',
        internal_id: '083365d2-b26e-4106-99e5-ace5e8c26a27',
        standard_id: 'relationship-meta--6833472e-7fac-4612-b778-5da0b46f719e',
        entity_type: 'object-label',
        from: null,
        fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
        fromRole: 'object-label_from',
        fromName: 'IR STUX 2.0',
        fromType: 'Case-Incident',
        source_ref: 'case-incident--temporary',
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
        _id: '300fbfc6-d862-45be-ac59-169b398b084e',
        id: '300fbfc6-d862-45be-ac59-169b398b084e',
        sort: [
          'relationship-meta--6bad591b-0852-4b55-be92-6bde3c3c8a8a'
        ],
        base_type: 'RELATION',
        internal_id: '300fbfc6-d862-45be-ac59-169b398b084e',
        standard_id: 'relationship-meta--6bad591b-0852-4b55-be92-6bde3c3c8a8a',
        entity_type: 'object-marking',
        from: null,
        fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
        fromRole: 'object-marking_from',
        fromName: 'IR STUX 2.0',
        fromType: 'Case-Incident',
        source_ref: 'case-incident--temporary',
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
  'object-assignee': [
    '0ff0750e-4d91-425d-b44c-b69269dead0b'
  ],
  objectAssignee: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      sort: [
        1750152527269
      ],
      user_email: 'marie.flores@filigran.io',
      name: 'marie',
      password: '$2a$10$GElYhi3IFp7bSu6jYNz/JO4tCVNWr6tVEXJXLr/npfbS.EYu/8YlC',
      firstname: '',
      lastname: '',
      description: '',
      account_status: 'Active',
      account_lock_after_date: null,
      user_confidence_level: null,
      api_token: 'dfd7ed5d-5374-4a2e-a088-4a4c0013ccd7',
      theme: 'default',
      language: 'auto',
      external: false,
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      confidence: 100,
      entity_type: 'User',
      internal_id: '0ff0750e-4d91-425d-b44c-b69269dead0b',
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-17T09:28:47.269Z',
      updated_at: '2025-06-17T09:28:47.332Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      modified: '2025-06-17T09:28:47.332Z',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'b7ed16a9-93d3-43fa-adb0-70e26aed7673',
        id: 'b7ed16a9-93d3-43fa-adb0-70e26aed7673',
        sort: [
          'relationship-meta--8a562b9e-c704-416f-8394-58799902e7bb'
        ],
        base_type: 'RELATION',
        internal_id: 'b7ed16a9-93d3-43fa-adb0-70e26aed7673',
        standard_id: 'relationship-meta--8a562b9e-c704-416f-8394-58799902e7bb',
        entity_type: 'object-assignee',
        from: null,
        fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
        fromRole: 'object-assignee_from',
        fromName: 'IR STUX 2.0',
        fromType: 'Case-Incident',
        source_ref: 'case-incident--temporary',
        to: null,
        toId: '0ff0750e-4d91-425d-b44c-b69269dead0b',
        toRole: 'object-assignee_to',
        toName: 'marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-assignee'
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
      _id: '047f033d-8278-4af4-b5d3-7b36d284f981',
      id: '047f033d-8278-4af4-b5d3-7b36d284f981',
      sort: [
        'relationship-meta--8c7696b1-7b40-48dd-9bd1-92b0ad1619c8'
      ],
      base_type: 'RELATION',
      internal_id: '047f033d-8278-4af4-b5d3-7b36d284f981',
      standard_id: 'relationship-meta--8c7696b1-7b40-48dd-9bd1-92b0ad1619c8',
      entity_type: 'created-by',
      from: null,
      fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
      fromRole: 'created-by_from',
      fromName: 'IR STUX 2.0',
      fromType: 'Case-Incident',
      source_ref: 'case-incident--temporary',
      to: null,
      toId: '0097209b-e5d7-43f2-b901-cf665df73f6b',
      toRole: 'created-by_to',
      toName: 'admin',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
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
        _id: 'd2c2f1fc-5a55-4cd1-8722-f5181f07b5c6',
        id: 'd2c2f1fc-5a55-4cd1-8722-f5181f07b5c6',
        sort: [
          'relationship-meta--d510640c-9aa7-4a57-ac40-f0f46a33caf8'
        ],
        base_type: 'RELATION',
        internal_id: 'd2c2f1fc-5a55-4cd1-8722-f5181f07b5c6',
        standard_id: 'relationship-meta--d510640c-9aa7-4a57-ac40-f0f46a33caf8',
        entity_type: 'external-reference',
        from: null,
        fromId: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
        fromRole: 'external-reference_from',
        fromName: 'IR STUX 2.0',
        fromType: 'Case-Incident',
        source_ref: 'case-incident--temporary',
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
} as unknown as StoreEntityCaseIncident2;

export const EXPECTED_IR = {
  id: 'x-opencti-case-incident--0ed8c294-d99f-5155-a54b-7cc3044174c3',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T16:06:02.000Z',
  modified: '2025-06-26T16:06:52.288Z',
  name: 'IR STIX 2.0',
  description: 'description',
  severity: 'medium',
  priority: 'P2',
  object_refs: [],
  response_types: [
    'data-leak'
  ],
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
  x_opencti_id: '4c849ab0-81f2-457c-b837-bea76f4d4d15',
  x_opencti_type: 'Case-Incident',
  type: 'x-opencti-case-incident',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Incident/4c849ab0-81f2-457c-b837-bea76f4d4d15/ipv4_example.json',
      version: '2025-06-26T16:06:52.222Z',
    },
  ],
  x_opencti_granted_refs: [],
};
