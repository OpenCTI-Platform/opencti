import type { StoreEntity } from '../../../../../src/types/store';

export const REPORT_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  sort: [
    1750948419653
  ],
  name: 'Report STIX 2.0',
  description: 'description',
  content: '<p>some content for my report about &nbsp;Disco Team Threat Actor Group</p>',
  published: '2025-06-26T14:32:10.000Z',
  report_types: [
    'internal-report'
  ],
  x_opencti_reliability: 'A - Completely reliable',
  confidence: 100,
  created: '2025-06-26T14:32:10.000Z',
  entity_type: 'Report',
  internal_id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  standard_id: 'report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T14:33:39.653Z',
  updated_at: '2025-06-26T14:36:58.281Z',
  revoked: false,
  lang: 'en',
  modified: '2025-06-26T14:36:51.467Z',
  x_opencti_workflow_id: 'b29268cc-bb75-4f28-96c9-4cb48e549dff',
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
      id: 'import/Report/0c38a734-3150-468f-bf38-8dc1f937a1b3/ipv4_example.json',
      name: 'ipv4_example.json',
      version: '2025-06-26T14:33:39.655Z',
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
      updated_at: '2025-06-26T14:36:51.468Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content'
    },
    {
      updated_at: '2025-06-26T14:36:58.233Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objects'
    },
    {
      updated_at: '2025-06-26T14:36:37.671Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'content_mapping'
    }
  ],
  content_mapping: 'eyJkaXNjbyB0ZWFtIHRocmVhdCBhY3RvciBncm91cCI6InRocmVhdC1hY3Rvci0tZmQ2YjBlNmYtOTZlMC01NjhkLWJhMjQtOGExNDBkMDQyOGNkIn0',
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
        _id: '292d401e-df4f-47ff-89f0-174cd7e52553',
        id: '292d401e-df4f-47ff-89f0-174cd7e52553',
        sort: [
          'relationship-meta--156b01cb-45cf-45da-9907-7ae046617024'
        ],
        base_type: 'RELATION',
        internal_id: '292d401e-df4f-47ff-89f0-174cd7e52553',
        standard_id: 'relationship-meta--156b01cb-45cf-45da-9907-7ae046617024',
        entity_type: 'object-assignee',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object-assignee_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
      _id: '11616813-abc0-4fbf-9b35-31793f814ff8',
      id: '11616813-abc0-4fbf-9b35-31793f814ff8',
      sort: [
        'relationship-meta--1de7f69c-c687-423b-b15f-0f58e45fc0ca'
      ],
      base_type: 'RELATION',
      internal_id: '11616813-abc0-4fbf-9b35-31793f814ff8',
      standard_id: 'relationship-meta--1de7f69c-c687-423b-b15f-0f58e45fc0ca',
      entity_type: 'created-by',
      from: null,
      fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
      fromRole: 'created-by_from',
      fromName: 'Report STIX 2.0',
      fromType: 'Report',
      source_ref: 'report--temporary',
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
    '5a3ff5f1-66ab-46c8-b5ce-67aebfaee6f5',
    'c808561d-ed59-4d54-914a-5d090eceafd6'
  ],
  objects: [
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
        _id: '48103821-876d-446d-8368-8b4246111164',
        id: '48103821-876d-446d-8368-8b4246111164',
        sort: [
          'relationship-meta--3eab20a6-7c94-4adf-a283-e828d6c16ac1'
        ],
        base_type: 'RELATION',
        internal_id: '48103821-876d-446d-8368-8b4246111164',
        standard_id: 'relationship-meta--3eab20a6-7c94-4adf-a283-e828d6c16ac1',
        entity_type: 'object',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
        _id: 'c92261ad-d17e-4ab0-a752-fd33aa9ccb86',
        id: 'c92261ad-d17e-4ab0-a752-fd33aa9ccb86',
        sort: [
          'relationship-meta--901a7eac-e855-483d-ad6b-b46a3fb992ea'
        ],
        base_type: 'RELATION',
        internal_id: 'c92261ad-d17e-4ab0-a752-fd33aa9ccb86',
        standard_id: 'relationship-meta--901a7eac-e855-483d-ad6b-b46a3fb992ea',
        entity_type: 'object',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
        _id: 'e1e203d5-b892-4d1d-ac64-63007c86e605',
        id: 'e1e203d5-b892-4d1d-ac64-63007c86e605',
        sort: [
          'relationship-meta--9c2089a8-dadf-454d-beeb-963ca14ed6a3'
        ],
        base_type: 'RELATION',
        internal_id: 'e1e203d5-b892-4d1d-ac64-63007c86e605',
        standard_id: 'relationship-meta--9c2089a8-dadf-454d-beeb-963ca14ed6a3',
        entity_type: 'external-reference',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'external-reference_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
        _id: 'da363089-412c-452a-95d2-ed8146e94eca',
        id: 'da363089-412c-452a-95d2-ed8146e94eca',
        sort: [
          'relationship-meta--b98b7725-b5a6-4d40-bd4b-f261f278d401'
        ],
        base_type: 'RELATION',
        internal_id: 'da363089-412c-452a-95d2-ed8146e94eca',
        standard_id: 'relationship-meta--b98b7725-b5a6-4d40-bd4b-f261f278d401',
        entity_type: 'object-marking',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object-marking_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
        _id: 'ca4b31b7-b269-4bba-bd99-30c24803bb4b',
        id: 'ca4b31b7-b269-4bba-bd99-30c24803bb4b',
        sort: [
          'relationship-meta--d742800b-e75c-4559-b175-060da45c7977'
        ],
        base_type: 'RELATION',
        internal_id: 'ca4b31b7-b269-4bba-bd99-30c24803bb4b',
        standard_id: 'relationship-meta--d742800b-e75c-4559-b175-060da45c7977',
        entity_type: 'object-participant',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object-participant_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
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
    '8e221bf3-bc58-4636-bf14-b23c89502fe1'
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '8e221bf3-bc58-4636-bf14-b23c89502fe1',
      id: '8e221bf3-bc58-4636-bf14-b23c89502fe1',
      sort: [
        1749548104126
      ],
      x_opencti_stix_ids: [],
      value: 'report',
      color: '#34554c',
      confidence: 100,
      entity_type: 'Label',
      internal_id: '8e221bf3-bc58-4636-bf14-b23c89502fe1',
      standard_id: 'label--a87ca076-f2b8-5374-a25b-103df133d9d3',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      created_at: '2025-06-10T09:35:04.126Z',
      updated_at: '2025-06-10T09:35:04.126Z',
      created: '2025-06-10T09:35:04.126Z',
      modified: '2025-06-10T09:35:04.126Z',
      base_type: 'ENTITY',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '7cea2ff8-18d0-4928-9154-6c462e855c66',
        id: '7cea2ff8-18d0-4928-9154-6c462e855c66',
        sort: [
          'relationship-meta--f3f75d36-7b65-4e17-9fae-88973d56888d'
        ],
        base_type: 'RELATION',
        internal_id: '7cea2ff8-18d0-4928-9154-6c462e855c66',
        standard_id: 'relationship-meta--f3f75d36-7b65-4e17-9fae-88973d56888d',
        entity_type: 'object-label',
        from: null,
        fromId: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
        fromRole: 'object-label_from',
        fromName: 'Report STIX 2.0',
        fromType: 'Report',
        source_ref: 'report--temporary',
        to: null,
        toId: '8e221bf3-bc58-4636-bf14-b23c89502fe1',
        toRole: 'object-label_to',
        toName: 'report',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreEntity;

export const EXPECTED_REPORT = {
  id: 'report--87de3e34-b9a2-551d-a42f-d25a13d4ad0f',
  spec_version: '2.0',
  revoked: false,
  x_opencti_reliability: 'A - Completely reliable',
  confidence: 100,
  created: '2025-06-26T14:32:10.000Z',
  modified: '2025-06-26T14:36:51.467Z',
  name: 'Report STIX 2.0',
  description: 'description',
  report_types: [
    'internal-report'
  ],
  published: '2025-06-26T14:32:10.000Z',
  x_opencti_workflow_id: 'b29268cc-bb75-4f28-96c9-4cb48e549dff',
  labels: [
    'report'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: '0c38a734-3150-468f-bf38-8dc1f937a1b3',
  x_opencti_type: 'Report',
  type: 'report',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
    'credential--4a194ac7-4aef-57d5-9a64-1312da4e604a'
  ],
  x_opencti_files: [
    {
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      object_marking_refs: [
        'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      ],
      uri: '/storage/get/import/Report/0c38a734-3150-468f-bf38-8dc1f937a1b3/ipv4_example.json',
      version: '2025-06-26T14:33:39.655Z',
    },
  ],
  x_opencti_granted_refs: [],
};
