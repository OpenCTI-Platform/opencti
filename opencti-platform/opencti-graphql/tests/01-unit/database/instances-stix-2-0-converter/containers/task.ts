import type { StoreEntityTask } from '../../../../../src/modules/task/task-types';

export const TASK_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  sort: [
    1750960529409
  ],
  name: 'task STIX 2.0',
  description: 'Description',
  created: '2025-06-26T17:55:28.987Z',
  confidence: 100,
  entity_type: 'Task',
  internal_id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  standard_id: 'task--8788511e-974c-571d-9a47-381299785038',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_stix_ids: [],
  created_at: '2025-06-26T17:55:29.409Z',
  updated_at: '2025-07-02T15:47:23.099Z',
  revoked: false,
  lang: 'en',
  modified: '2025-07-02T15:46:34.373Z',
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
      updated_at: '2025-06-26T18:03:23.571Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'description'
    },
    {
      updated_at: '2025-06-26T18:03:25.894Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectAssignee'
    },
    {
      updated_at: '2025-06-26T18:03:28.096Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectParticipant'
    },
    {
      updated_at: '2025-06-26T18:03:43.146Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectOrganization'
    },
    {
      updated_at: '2025-06-26T18:03:54.113Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'due_date'
    },
    {
      updated_at: '2025-06-26T18:04:32.619Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'name'
    },
    {
      updated_at: '2025-06-26T18:04:32.619Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'standard_id'
    },
    {
      updated_at: '2025-07-02T15:46:34.278Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectLabel'
    }
  ],
  due_date: '2025-06-27T22:00:00.000Z',
  x_opencti_files: [
    {
      file_markings: [],
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      id: 'import/Task/d4e02a21-0dda-4295-be80-3c81503b69c8/ipv4_example.json',
      version: '2025-07-02T15:47:23.032Z'
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
      password: '$2a$10$akF3LCkuTuU4C3o1DKmFeOEXWhdUL0WyBO9740MNbD9I8osQbFzEq',
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
      updated_at: '2025-07-02T15:50:29.209Z',
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
          updated_at: '2025-07-02T15:50:29.218Z',
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
        _id: 'a3a83dcd-47c0-4afc-9c9a-53fa45734697',
        id: 'a3a83dcd-47c0-4afc-9c9a-53fa45734697',
        sort: [
          'relationship-meta--21dc3717-ddb7-42bc-835b-4b2bd11cc7f8'
        ],
        standard_id: 'relationship-meta--21dc3717-ddb7-42bc-835b-4b2bd11cc7f8',
        base_type: 'RELATION',
        entity_type: 'object-assignee',
        internal_id: 'a3a83dcd-47c0-4afc-9c9a-53fa45734697',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'object-assignee_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
        to: null,
        toId: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        toRole: 'object-assignee_to',
        toName: 'admin',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-assignee'
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
        _id: 'e34b69f8-b2b9-4161-9cbe-e2d44ef81c54',
        id: 'e34b69f8-b2b9-4161-9cbe-e2d44ef81c54',
        sort: [
          'relationship-meta--61d01089-afe9-471d-aeef-7e8e1bb41bcc'
        ],
        standard_id: 'relationship-meta--61d01089-afe9-471d-aeef-7e8e1bb41bcc',
        base_type: 'RELATION',
        entity_type: 'granted',
        internal_id: 'e34b69f8-b2b9-4161-9cbe-e2d44ef81c54',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'granted_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
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
        _id: '9bf41d01-be91-47fc-8d0f-03ed0d64a562',
        id: '9bf41d01-be91-47fc-8d0f-03ed0d64a562',
        sort: [
          'relationship-meta--70cf96da-2889-42f7-afd0-7c06a01d2133'
        ],
        standard_id: 'relationship-meta--70cf96da-2889-42f7-afd0-7c06a01d2133',
        base_type: 'RELATION',
        entity_type: 'object-marking',
        internal_id: '9bf41d01-be91-47fc-8d0f-03ed0d64a562',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'object-marking_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
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
        _id: 'b4d809b1-844d-4239-9e9e-0f55066ac3e9',
        id: 'b4d809b1-844d-4239-9e9e-0f55066ac3e9',
        sort: [
          'relationship-meta--969bd487-81c2-4b0b-a5cf-fa1a09736ff2'
        ],
        base_type: 'RELATION',
        internal_id: 'b4d809b1-844d-4239-9e9e-0f55066ac3e9',
        standard_id: 'relationship-meta--969bd487-81c2-4b0b-a5cf-fa1a09736ff2',
        entity_type: 'object-label',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'object-label_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
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
  'object-participant': [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  objectParticipant: [
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
      password: '$2a$10$akF3LCkuTuU4C3o1DKmFeOEXWhdUL0WyBO9740MNbD9I8osQbFzEq',
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
      updated_at: '2025-07-02T15:50:29.209Z',
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
          updated_at: '2025-07-02T15:50:29.218Z',
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
        _id: '4e06ad55-0926-422c-a6da-c2653262b718',
        id: '4e06ad55-0926-422c-a6da-c2653262b718',
        sort: [
          'relationship-meta--bca0c9f3-a39d-4386-954f-73011ac81e80'
        ],
        standard_id: 'relationship-meta--bca0c9f3-a39d-4386-954f-73011ac81e80',
        base_type: 'RELATION',
        entity_type: 'object-participant',
        internal_id: '4e06ad55-0926-422c-a6da-c2653262b718',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'object-participant_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
        to: null,
        toId: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        toRole: 'object-participant_to',
        toName: 'admin',
        toType: 'User',
        target_ref: 'user--temporary',
        relationship_type: 'object-participant'
      }
    }
  ],
  object: [
    'ae110ba9-34a7-44ef-86b9-7b52def4b4aa'
  ],
  objects: [
    {
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
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '51b96841-9076-4215-8dee-0d89e1f42d4d',
        id: '51b96841-9076-4215-8dee-0d89e1f42d4d',
        sort: [
          'relationship-meta--f88f82fd-a295-4a3f-a6d3-e8e70708307e'
        ],
        standard_id: 'relationship-meta--f88f82fd-a295-4a3f-a6d3-e8e70708307e',
        base_type: 'RELATION',
        entity_type: 'object',
        internal_id: '51b96841-9076-4215-8dee-0d89e1f42d4d',
        from: null,
        fromId: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
        fromRole: 'object_from',
        fromName: 'task STIX 2.0',
        fromType: 'Task',
        source_ref: 'task--temporary',
        to: null,
        toId: 'ae110ba9-34a7-44ef-86b9-7b52def4b4aa',
        toRole: 'object_to',
        toName: 'RFT STIX 2.0',
        toType: 'Case-Rft',
        target_ref: 'case-rft--temporary',
        relationship_type: 'object'
      }
    }
  ]
} as unknown as StoreEntityTask;

export const EXPECTED_TASK = {
  id: 'x-opencti-task--8788511e-974c-571d-9a47-381299785038',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:55:28.987Z',
  modified: '2025-07-02T15:46:34.373Z',
  name: 'task STIX 2.0',
  description: 'Description',
  due_date: '2025-06-27T22:00:00.000Z',
  labels: [
    'ryuk'
  ],
  x_opencti_id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  x_opencti_type: 'Task',
  type: 'x-opencti-task',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  object_refs: [
    'case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763'
  ],
  created_by_ref: undefined,
  x_opencti_files: [{
    mime_type: 'application/json',
    name: 'ipv4_example.json',
    object_marking_refs: [],
    uri: '/storage/get/import/Task/d4e02a21-0dda-4295-be80-3c81503b69c8/ipv4_example.json',
    version: '2025-07-02T15:47:23.032Z',
  }],
  external_references: [],
  x_opencti_granted_refs: [
    'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  ],
};
