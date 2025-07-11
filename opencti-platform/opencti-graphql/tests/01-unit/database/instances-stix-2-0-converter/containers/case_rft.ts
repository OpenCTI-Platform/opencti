import type { StoreEntityCaseRft2 } from '../../../../../src/modules/case/case-rft/case-rft-types';

export const RFT_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  sort: [
    1750960528869
  ],
  name: 'RFT STIX 2.0',
  description: 'description',
  content: '<p>content: Disco Team Threat Actor Group</p>',
  severity: 'medium',
  priority: 'P2',
  confidence: 100,
  created: '2025-06-26T17:54:43.000Z',
  takedown_types: [
    'brand-abuse'
  ],
  entity_type: 'Case-Rft',
  internal_id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  standard_id: 'case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T17:55:28.869Z',
  updated_at: '2025-06-26T17:56:37.718Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T17:56:37.718Z',
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
      id: 'import/Case-Rft/ae110ba9-34a7-44ef-86b9-7b52def4b4aa/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T17:55:28.870Z',
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
      updated_at: '2025-06-26T17:55:59.113Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content'
    },
    {
      updated_at: '2025-06-26T17:56:21.251Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T17:56:06.869Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content_mapping'
    },
    {
      updated_at: '2025-06-26T17:56:37.719Z',
      user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
      confidence: 100,
      name: 'opinions_metrics'
    }
  ],
  content_mapping: 'eyJkaXNjbyB0ZWFtIHRocmVhdCBhY3RvciBncm91cCI6InRocmVhdC1hY3Rvci0tZmQ2YjBlNmYtOTZlMC01NjhkLWJhMjQtOGExNDBkMDQyOGNkIn0',
  opinions_metrics: {
    total: 1,
    min: 2,
    max: 2,
    mean: 2
  },
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
      _id: '59067c25-c49f-4824-ae9c-8f939dcd8146',
      id: '59067c25-c49f-4824-ae9c-8f939dcd8146',
      sort: [
        'relationship-meta--35d1f0f0-3c9a-4273-82b7-ff5740b6a982'
      ],
      base_type: 'RELATION',
      internal_id: '59067c25-c49f-4824-ae9c-8f939dcd8146',
      standard_id: 'relationship-meta--35d1f0f0-3c9a-4273-82b7-ff5740b6a982',
      entity_type: 'created-by',
      from: null,
      fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
      fromRole: 'created-by_from',
      fromName: 'RFT STIX 2.0',
      fromType: 'Case-Rft',
      source_ref: 'case-rft--temporary',
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
        _id: '29b60b32-9a49-48ec-9add-68ea6941e4b8',
        id: '29b60b32-9a49-48ec-9add-68ea6941e4b8',
        sort: [
          'relationship-meta--386a2899-c082-41b9-a0bf-61191cdf3b67'
        ],
        base_type: 'RELATION',
        internal_id: '29b60b32-9a49-48ec-9add-68ea6941e4b8',
        standard_id: 'relationship-meta--386a2899-c082-41b9-a0bf-61191cdf3b67',
        entity_type: 'external-reference',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'external-reference_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
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
        _id: '26cdbe2f-cf75-4f4a-b9f5-f6158efac9ce',
        id: '26cdbe2f-cf75-4f4a-b9f5-f6158efac9ce',
        sort: [
          'relationship-meta--4ac04aca-d11d-4fd4-b3ff-09bbf6404ef0'
        ],
        base_type: 'RELATION',
        internal_id: '26cdbe2f-cf75-4f4a-b9f5-f6158efac9ce',
        standard_id: 'relationship-meta--4ac04aca-d11d-4fd4-b3ff-09bbf6404ef0',
        entity_type: 'object-marking',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object-marking_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
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
  object: [
    'c808561d-ed59-4d54-914a-5d090eceafd6',
    '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
    '2e4b754a-9990-4ddb-89a4-527f18368f9b'
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
        _id: 'dedd7d82-8244-4ca4-90f0-a4f97ad426ca',
        id: 'dedd7d82-8244-4ca4-90f0-a4f97ad426ca',
        sort: [
          'relationship-meta--85f73570-b2bd-46f7-b385-b3bc58fb78bd'
        ],
        base_type: 'RELATION',
        internal_id: 'dedd7d82-8244-4ca4-90f0-a4f97ad426ca',
        standard_id: 'relationship-meta--85f73570-b2bd-46f7-b385-b3bc58fb78bd',
        entity_type: 'object',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
        to: null,
        toId: 'c808561d-ed59-4d54-914a-5d090eceafd6',
        toRole: 'object_to',
        toName: 'azerty',
        toType: 'Credential',
        target_ref: 'credential--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
      id: '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
      sort: [
        1749547930988
      ],
      x_opencti_stix_ids: [
        'threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428'
      ],
      name: 'Disco Team Threat Actor Group',
      description: 'This organized threat actor group operates to create profit from all types of crime.',
      aliases: [
        'Equipo del Discoteca'
      ],
      threat_actor_types: [
        'crime-syndicate'
      ],
      first_seen: '1970-01-01T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
      goals: [
        'Steal Credit Card Information'
      ],
      sophistication: 'expert',
      resource_level: 'organization',
      primary_motivation: 'personal-gain',
      secondary_motivations: null,
      personal_motivations: null,
      confidence: 100,
      revoked: false,
      lang: 'en',
      created: '2018-11-19T23:39:03.893Z',
      modified: '2025-06-10T09:32:11.003Z',
      x_opencti_workflow_id: null,
      entity_type: 'Threat-Actor-Group',
      internal_id: '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
      standard_id: 'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:10.988Z',
      updated_at: '2025-06-10T09:32:11.003Z',
      i_aliases_ids: [
        'threat-actor--e91d383c-d377-5e7b-8386-36cf8ce110f9'
      ],
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Core-Object',
        'Stix-Domain-Object',
        'Threat-Actor'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'bf5deb4b-0a9c-48f8-8164-d270f0afca35',
        id: 'bf5deb4b-0a9c-48f8-8164-d270f0afca35',
        sort: [
          'relationship-meta--90919caf-de10-434f-b9ee-4f71cea9e48c'
        ],
        base_type: 'RELATION',
        internal_id: 'bf5deb4b-0a9c-48f8-8164-d270f0afca35',
        standard_id: 'relationship-meta--90919caf-de10-434f-b9ee-4f71cea9e48c',
        entity_type: 'object',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
        to: null,
        toId: '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
        toRole: 'object_to',
        toName: 'Disco Team Threat Actor Group',
        toType: 'Threat-Actor-Group',
        target_ref: 'threat-actor--temporary',
        relationship_type: 'object'
      }
    },
    {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      sort: [
        1749547951501
      ],
      x_opencti_stix_ids: [
        'incident--0b626d41-1d8d-4b96-86fa-ad49cea2cfd4'
      ],
      name: 'A new incident',
      description: 'A test incident',
      confidence: 100,
      revoked: false,
      lang: 'en',
      objective: null,
      first_seen: '2020-02-27T08:45:47.779Z',
      last_seen: '2020-02-27T08:45:47.779Z',
      aliases: null,
      incident_type: null,
      severity: null,
      source: null,
      created: '2020-03-25T14:48:31.601Z',
      modified: '2025-06-10T09:34:51.852Z',
      x_opencti_workflow_id: null,
      entity_type: 'Incident',
      internal_id: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
      standard_id: 'incident--8658860d-df08-5f41-bf41-106095e48085',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:32:31.501Z',
      updated_at: '2025-06-10T09:34:51.852Z',
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
          updated_at: '2025-06-10T09:34:51.852Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'opinions_metrics'
        }
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'cc5af488-5703-45b1-a380-ff18029fa924',
        id: 'cc5af488-5703-45b1-a380-ff18029fa924',
        sort: [
          'relationship-meta--e713362c-12c2-4cb5-865b-c497e103dfef'
        ],
        base_type: 'RELATION',
        internal_id: 'cc5af488-5703-45b1-a380-ff18029fa924',
        standard_id: 'relationship-meta--e713362c-12c2-4cb5-865b-c497e103dfef',
        entity_type: 'object',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
        to: null,
        toId: '2e4b754a-9990-4ddb-89a4-527f18368f9b',
        toRole: 'object_to',
        toName: 'A new incident',
        toType: 'Incident',
        target_ref: 'incident--temporary',
        relationship_type: 'object'
      }
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
        _id: 'c9e31e43-6fcc-469a-95bf-ac63a863f28a',
        id: 'c9e31e43-6fcc-469a-95bf-ac63a863f28a',
        sort: [
          'relationship-meta--9937c60d-7a59-4187-a73b-870a163363a2'
        ],
        base_type: 'RELATION',
        internal_id: 'c9e31e43-6fcc-469a-95bf-ac63a863f28a',
        standard_id: 'relationship-meta--9937c60d-7a59-4187-a73b-870a163363a2',
        entity_type: 'object-participant',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object-participant_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
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
        _id: '7ee75ec4-5eb4-4f09-8c5f-790a26f418c0',
        id: '7ee75ec4-5eb4-4f09-8c5f-790a26f418c0',
        sort: [
          'relationship-meta--aa9732fa-7537-4676-af81-336ce2543701'
        ],
        base_type: 'RELATION',
        internal_id: '7ee75ec4-5eb4-4f09-8c5f-790a26f418c0',
        standard_id: 'relationship-meta--aa9732fa-7537-4676-af81-336ce2543701',
        entity_type: 'object-label',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object-label_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
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
  'object-assignee': [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  objectAssignee: [
    {
      _index: 'opencti_internal_objects-000001',
      _id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      sort: [
        1749546768092
      ],
      internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      external: true,
      user_email: 'admin@opencti.io',
      account_status: 'Active',
      name: 'admin',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      description: 'Principal admin account',
      api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e84',
      password: '$2a$10$Xl2OL3QrDVbbvyUF2bedW.gEBvVBxIgIBXGDWeOuq9tygRELvoOh6',
      user_confidence_level: {
        max_confidence: 100,
        overrides: []
      },
      theme: 'default',
      language: 'en-us',
      personal_notifiers: [
        'f4ee7b33-006a-4b0d-b57d-411ad288653d',
        '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822'
      ],
      confidence: 100,
      entity_type: 'User',
      standard_id: 'user--12ea8141-dc6d-5031-9a1b-c28aeac7198b',
      creator_id: [
        '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
      ],
      created_at: '2025-06-10T09:12:48.092Z',
      updated_at: '2025-06-26T14:28:09.367Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      i_attributes: [
        {
          updated_at: '2025-06-10T09:38:27.289Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'language'
        },
        {
          updated_at: '2025-06-26T14:28:09.377Z',
          user_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          confidence: 100,
          name: 'password'
        },
        {
          updated_at: '2025-06-19T08:59:42.526Z',
          user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          confidence: 100,
          name: 'draft_context'
        }
      ],
      draft_context: '',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '109ab876-ad5b-4dd6-89b1-c8fb5ce07847',
        id: '109ab876-ad5b-4dd6-89b1-c8fb5ce07847',
        sort: [
          'relationship-meta--fdc563ab-d5ba-447c-9d3c-c5f0662bcf86'
        ],
        base_type: 'RELATION',
        internal_id: '109ab876-ad5b-4dd6-89b1-c8fb5ce07847',
        standard_id: 'relationship-meta--fdc563ab-d5ba-447c-9d3c-c5f0662bcf86',
        entity_type: 'object-assignee',
        from: null,
        fromId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        fromRole: 'object-assignee_from',
        fromName: 'RFT STIX 2.0',
        fromType: 'Case-Rft',
        source_ref: 'case-rft--temporary',
        to: null,
        toId: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        toRole: 'object-assignee_to',
        toName: 'admin',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-assignee'
      }
    }
  ]
} as unknown as StoreEntityCaseRft2;

export const EXPECTED_RFT = {
  id: 'x-opencti-case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:54:43.000Z',
  modified: '2025-06-26T17:56:37.718Z',
  name: 'RFT STIX 2.0',
  description: 'description',
  takedown_types: [
    'brand-abuse'
  ],
  severity: 'medium',
  priority: 'P2',
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
  x_opencti_id: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
  x_opencti_type: 'Case-Rft',
  type: 'x-opencti-case-rft',
  created_by_ref: 'identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a',
    'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
    'incident--8658860d-df08-5f41-bf41-106095e48085',
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Case-Rft/ae110ba9-34a7-44ef-86b9-7b52def4b4aa/ipv4_example.json',
      version: '2025-06-26T17:55:28.870Z',
    },
  ],
  x_opencti_granted_refs: [],
};
