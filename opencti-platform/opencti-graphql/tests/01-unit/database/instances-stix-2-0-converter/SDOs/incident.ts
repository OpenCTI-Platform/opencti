import type { StoreEntity } from '../../../../../src/types/store';

export const INCIDENT_INSTANCE = {

  _index: 'opencti_stix_domain_objects-000001',
  _id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  sort: [
    1753892766239
  ],
  standard_id: 'incident--4e110b9d-8c95-581e-8618-4be501bcbe06',
  incident_type: 'alert',
  first_seen: '2025-07-24T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object'
  ],
  i_attributes: [
    {
      updated_at: '2025-07-30T16:28:25.083Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'first_seen'
    },
    {
      updated_at: '2025-07-30T16:28:29.489Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'last_seen'
    },
    {
      updated_at: '2025-07-30T16:30:00.845Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'source'
    },
    {
      updated_at: '2025-07-30T16:30:20.565Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objective'
    },
    {
      updated_at: '2025-07-30T16:30:34.591Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'description'
    },
    {
      updated_at: '2025-07-30T16:38:27.946Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectOrganization'
    }
  ],
  description: 'description',
  created_at: '2025-07-30T16:26:06.239Z',
  source: 'secret',
  revoked: false,
  objective: 'destruction',
  base_type: 'ENTITY',
  updated_at: '2025-07-30T18:52:14.947Z',
  modified: '2025-07-30T18:52:14.947Z',
  i_aliases_ids: [],
  lang: 'en',
  severity: 'medium',
  internal_id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  created: '2025-07-30T16:26:06.212Z',
  confidence: 100,
  entity_type: 'Incident',
  name: 'Incident Stix 2.0',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  'rel_created-by.internal_id.keyword': [
    '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75'
  ],
  'rel_object-participant.internal_id.keyword': [
    '51c085a6-612a-463b-9575-27513bf85d99'
  ],
  'rel_object-label.internal_id.keyword': [
    'ad9a877b-d550-492f-a39e-3be894b16296'
  ],
  'rel_granted.internal_id.keyword': [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'rel_object-marking.internal_id.keyword': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
  ],
  'rel_object-assignee.internal_id.keyword': [
    '51c085a6-612a-463b-9575-27513bf85d99'
  ],
  'created-by': '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75',
  'object-participant': [
    '51c085a6-612a-463b-9575-27513bf85d99'
  ],
  'object-label': [
    'ad9a877b-d550-492f-a39e-3be894b16296'
  ],
  granted: [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'object-marking': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
  ],
  'object-assignee': [
    '51c085a6-612a-463b-9575-27513bf85d99'
  ],
  objectMarking: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '1af26c84-a670-4ea4-b420-9c9639519142',
      id: '1af26c84-a670-4ea4-b420-9c9639519142',
      sort: [
        1752671047216
      ],
      standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
      x_opencti_color: '#2e7d32',
      x_opencti_order: 2,
      internal_id: '1af26c84-a670-4ea4-b420-9c9639519142',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      definition_type: 'PAP',
      created: '2025-07-16T13:04:07.216Z',
      confidence: 100,
      created_at: '2025-07-16T13:04:07.216Z',
      entity_type: 'Marking-Definition',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:04:07.216Z',
      creator_id: [
        '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
      ],
      modified: '2025-07-16T13:04:07.216Z',
      definition: 'PAP:GREEN',
      x_opencti_stix_ids: [],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '9e733e5a-693d-414c-8eb0-dd0905cf02e2',
        id: '9e733e5a-693d-414c-8eb0-dd0905cf02e2',
        sort: [
          'relationship-meta--2d65c6b9-ac3b-4d9d-ae4e-03de18714900'
        ],
        standard_id: 'relationship-meta--2d65c6b9-ac3b-4d9d-ae4e-03de18714900',
        base_type: 'RELATION',
        entity_type: 'object-marking',
        internal_id: '9e733e5a-693d-414c-8eb0-dd0905cf02e2',
        from: null,
        fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
        fromRole: 'object-marking_from',
        fromName: 'Incident Stix 2.0',
        fromType: 'Incident',
        source_ref: 'incident--temporary',
        to: null,
        toId: '1af26c84-a670-4ea4-b420-9c9639519142',
        toRole: 'object-marking_to',
        toName: 'PAP:GREEN',
        toType: 'Marking-Definition',
        target_ref: 'marking-definition--temporary',
        relationship_type: 'object-marking'
      }
    }
  ],
  objectOrganization: [
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '079db495-ef69-402b-b28f-31953b770f0f',
      id: '079db495-ef69-402b-b28f-31953b770f0f',
      sort: [
        1752673177465
      ],
      standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
      identity_class: 'organization',
      x_opencti_organization_type: 'csirt',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object',
        'Identity'
      ],
      roles: null,
      description: null,
      contact_information: null,
      created_at: '2025-07-16T13:39:37.465Z',
      x_opencti_aliases: null,
      revoked: false,
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:37.477Z',
      modified: '2025-07-16T13:39:37.477Z',
      i_aliases_ids: [],
      lang: 'en',
      x_opencti_workflow_id: null,
      internal_id: '079db495-ef69-402b-b28f-31953b770f0f',
      x_opencti_reliability: 'A - Completely reliable',
      created: '2020-02-23T23:40:53.575Z',
      confidence: 100,
      entity_type: 'Organization',
      name: 'ANSSI',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [
        'identity--7b82b010-b1c0-4dae-981f-7756374a17df'
      ],
      'rel_object-label.internal_id.keyword': [
        '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
      ],
      'object-label': [
        '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '1fa76cc2-57c6-4ecd-9578-12ec48594be9',
        id: '1fa76cc2-57c6-4ecd-9578-12ec48594be9',
        sort: [
          'relationship-meta--3dd03996-933c-4253-9fcd-93fa866b60ee'
        ],
        standard_id: 'relationship-meta--3dd03996-933c-4253-9fcd-93fa866b60ee',
        base_type: 'RELATION',
        entity_type: 'granted',
        internal_id: '1fa76cc2-57c6-4ecd-9578-12ec48594be9',
        from: null,
        fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
        fromRole: 'granted_from',
        fromName: 'Incident Stix 2.0',
        fromType: 'Incident',
        source_ref: 'incident--temporary',
        to: null,
        toId: '079db495-ef69-402b-b28f-31953b770f0f',
        toRole: 'granted_to',
        toName: 'ANSSI',
        toType: 'Organization',
        target_ref: 'identity--temporary',
        relationship_type: 'granted'
      }
    }
  ],
  objectAssignee: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '51c085a6-612a-463b-9575-27513bf85d99',
      id: '51c085a6-612a-463b-9575-27513bf85d99',
      sort: [
        1752673654588
      ],
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      firstname: '',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      api_token: '67231010-56fd-4e2e-9447-82c70b7ffe43',
      description: '',
      created_at: '2025-07-16T13:47:34.588Z',
      language: 'auto',
      account_status: 'Active',
      password: '$2a$10$G9qqvwJdzgeKn2sy8s7hvue1l1oyBvPhE1Xe.eNHhHfBYOP.fN.3.',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:47:34.588Z',
      user_service_account: false,
      account_lock_after_date: null,
      theme: 'default',
      user_confidence_level: null,
      user_email: 'marie.flores@filigran.io',
      internal_id: '51c085a6-612a-463b-9575-27513bf85d99',
      confidence: 100,
      lastname: '',
      external: false,
      entity_type: 'User',
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      name: 'Marie',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '82904238-3f88-4837-bce9-fe95bd214637',
        id: '82904238-3f88-4837-bce9-fe95bd214637',
        sort: [
          'relationship-meta--7de28e5f-3bed-41cc-a9fa-c2eeda7fa053'
        ],
        standard_id: 'relationship-meta--7de28e5f-3bed-41cc-a9fa-c2eeda7fa053',
        base_type: 'RELATION',
        entity_type: 'object-assignee',
        internal_id: '82904238-3f88-4837-bce9-fe95bd214637',
        from: null,
        fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
        fromRole: 'object-assignee_from',
        fromName: 'Incident Stix 2.0',
        fromType: 'Incident',
        source_ref: 'incident--temporary',
        to: null,
        toId: '51c085a6-612a-463b-9575-27513bf85d99',
        toRole: 'object-assignee_to',
        toName: 'Marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-assignee'
      }
    }
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'ad9a877b-d550-492f-a39e-3be894b16296',
      id: 'ad9a877b-d550-492f-a39e-3be894b16296',
      sort: [
        1752673180313
      ],
      standard_id: 'label--11456f4c-8be3-5c50-b9ee-d1279df6730b',
      color: '#d0ac39',
      internal_id: 'ad9a877b-d550-492f-a39e-3be894b16296',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:40.313Z',
      confidence: 100,
      created_at: '2025-07-16T13:39:40.313Z',
      entity_type: 'Label',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:40.313Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:40.313Z',
      x_opencti_stix_ids: [],
      value: 'covid-19',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'ec7ced5c-ab55-4449-98d6-3fa0ea8311a4',
        id: 'ec7ced5c-ab55-4449-98d6-3fa0ea8311a4',
        sort: [
          'relationship-meta--864567d4-5853-43f2-9514-d042e3606655'
        ],
        standard_id: 'relationship-meta--864567d4-5853-43f2-9514-d042e3606655',
        base_type: 'RELATION',
        entity_type: 'object-label',
        internal_id: 'ec7ced5c-ab55-4449-98d6-3fa0ea8311a4',
        from: null,
        fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
        fromRole: 'object-label_from',
        fromName: 'Incident Stix 2.0',
        fromType: 'Incident',
        source_ref: 'incident--temporary',
        to: null,
        toId: 'ad9a877b-d550-492f-a39e-3be894b16296',
        toRole: 'object-label_to',
        toName: 'covid-19',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ],
  createdBy: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75',
    id: '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75',
    sort: [
      1752673669323
    ],
    standard_id: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
    identity_class: 'organization',
    internal_id: '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Core-Object',
      'Stix-Domain-Object',
      'Identity'
    ],
    i_attributes: [
      {
        updated_at: '2025-07-29T14:59:15.851Z',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        confidence: 100,
        name: 'authorized_authorities'
      }
    ],
    created: '2025-07-16T13:47:49.323Z',
    confidence: 100,
    authorized_authorities: [
      'a223dd31-d7d9-4ddd-93d5-64d6abe91d36'
    ],
    description: '',
    created_at: '2025-07-16T13:47:49.323Z',
    revoked: false,
    entity_type: 'Organization',
    base_type: 'ENTITY',
    updated_at: '2025-07-29T14:59:15.851Z',
    name: 'Filigran',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    modified: '2025-07-29T14:59:15.851Z',
    i_aliases_ids: [],
    x_opencti_stix_ids: [],
    lang: 'en',
    i_relation: {
      _index: 'opencti_stix_meta_relationships-000001',
      _id: '08d29579-6a78-4722-8619-be010fbc560e',
      id: '08d29579-6a78-4722-8619-be010fbc560e',
      sort: [
        'relationship-meta--8e2178c6-59f6-4086-be63-d755f7c3864d'
      ],
      standard_id: 'relationship-meta--8e2178c6-59f6-4086-be63-d755f7c3864d',
      base_type: 'RELATION',
      entity_type: 'created-by',
      internal_id: '08d29579-6a78-4722-8619-be010fbc560e',
      from: null,
      fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
      fromRole: 'created-by_from',
      fromName: 'Incident Stix 2.0',
      fromType: 'Incident',
      source_ref: 'incident--temporary',
      to: null,
      toId: '81f4b1fa-a1a0-46ff-8782-5f29e23f9a75',
      toRole: 'created-by_to',
      toName: 'Filigran',
      toType: 'Organization',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
  objectParticipant: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '51c085a6-612a-463b-9575-27513bf85d99',
      id: '51c085a6-612a-463b-9575-27513bf85d99',
      sort: [
        1752673654588
      ],
      standard_id: 'user--20e40687-5a83-5a19-ba58-ca14e88fdbd1',
      firstname: '',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      api_token: '67231010-56fd-4e2e-9447-82c70b7ffe43',
      description: '',
      created_at: '2025-07-16T13:47:34.588Z',
      language: 'auto',
      account_status: 'Active',
      password: '$2a$10$G9qqvwJdzgeKn2sy8s7hvue1l1oyBvPhE1Xe.eNHhHfBYOP.fN.3.',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:47:34.588Z',
      user_service_account: false,
      account_lock_after_date: null,
      theme: 'default',
      user_confidence_level: null,
      user_email: 'marie.flores@filigran.io',
      internal_id: '51c085a6-612a-463b-9575-27513bf85d99',
      confidence: 100,
      lastname: '',
      external: false,
      entity_type: 'User',
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      name: 'Marie',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '9566b871-a47c-46c2-8a88-46cf8f862a4a',
        id: '9566b871-a47c-46c2-8a88-46cf8f862a4a',
        sort: [
          'relationship-meta--b8978e38-7886-4422-95f2-0efc85b55f29'
        ],
        standard_id: 'relationship-meta--b8978e38-7886-4422-95f2-0efc85b55f29',
        base_type: 'RELATION',
        entity_type: 'object-participant',
        internal_id: '9566b871-a47c-46c2-8a88-46cf8f862a4a',
        from: null,
        fromId: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
        fromRole: 'object-participant_from',
        fromName: 'Incident Stix 2.0',
        fromType: 'Incident',
        source_ref: 'incident--temporary',
        to: null,
        toId: '51c085a6-612a-463b-9575-27513bf85d99',
        toRole: 'object-participant_to',
        toName: 'Marie',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-participant'
      }
    }
  ]
} as unknown as StoreEntity;

export const EXPECTED_INCIDENT = {
  id: 'incident--4e110b9d-8c95-581e-8618-4be501bcbe06',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-07-30T16:26:06.212Z',
  modified: '2025-07-30T18:52:14.947Z',
  name: 'Incident Stix 2.0',
  description: 'description',
  first_seen: '2025-07-24T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  objective: 'destruction',
  incident_type: 'alert',
  severity: 'medium',
  source: 'secret',
  labels: [
    'covid-19'
  ],
  x_opencti_id: '232a5554-6d8f-4b1b-aaee-48ee6a6c7b0d',
  x_opencti_type: 'Incident',
  type: 'incident',
  x_opencti_files: [],
  created_by_ref: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  x_opencti_granted_refs: [
    'identity--18fe5225-fee1-5627-ad3e-20c14435b024'
  ],
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
  ],
  external_references: []
};
