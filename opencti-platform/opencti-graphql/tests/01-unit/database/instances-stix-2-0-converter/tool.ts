import type { StoreEntity } from '../../../../src/types/store';

export const TOOL_INSTANCE = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: 'c914c155-5672-432d-9904-c7981d81caa5',
  id: 'c914c155-5672-432d-9904-c7981d81caa5',
  sort: [
    1754061829755
  ],
  standard_id: 'tool--a8bdbff3-16b4-5cd2-b112-ee7a7b1f359c',
  internal_id: 'c914c155-5672-432d-9904-c7981d81caa5',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object'
  ],
  created: '2025-08-01T15:23:49.755Z',
  confidence: 100,
  description: 'description',
  created_at: '2025-08-01T15:23:49.755Z',
  revoked: false,
  entity_type: 'Tool',
  base_type: 'ENTITY',
  updated_at: '2025-08-01T15:29:11.399Z',
  tool_version: '2',
  name: 'Tool Stix 2.0',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  modified: '2025-08-01T15:29:11.399Z',
  i_aliases_ids: [],
  tool_types: [
    'denial-of-service'
  ],
  x_opencti_stix_ids: [],
  lang: 'en',
  'rel_created-by.internal_id.keyword': [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'rel_object-label.internal_id.keyword': [
    '639956e1-a6b9-4aa8-bb79-55f97af280b3'
  ],
  'rel_object-marking.internal_id.keyword': [
    'c716bc3f-4b39-4911-b2ba-c972d15cff15'
  ],
  'rel_kill-chain-phase.internal_id.keyword': [
    'dd7d2257-a65e-4d74-a8fa-1472cf593aa4'
  ],
  'created-by': '079db495-ef69-402b-b28f-31953b770f0f',
  'object-label': [
    '639956e1-a6b9-4aa8-bb79-55f97af280b3'
  ],
  'object-marking': [
    'c716bc3f-4b39-4911-b2ba-c972d15cff15'
  ],
  'kill-chain-phase': [
    'dd7d2257-a65e-4d74-a8fa-1472cf593aa4'
  ],
  'external-reference': [
    '40cba5a9-e7a6-4c6d-b3da-d0c929159a35'
  ],
  externalReferences: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '40cba5a9-e7a6-4c6d-b3da-d0c929159a35',
      id: '40cba5a9-e7a6-4c6d-b3da-d0c929159a35',
      sort: [
        1752673177601
      ],
      standard_id: 'external-reference--4a67461d-68b8-5a27-996f-a8e30578cb56',
      internal_id: '40cba5a9-e7a6-4c6d-b3da-d0c929159a35',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:37.601Z',
      confidence: 100,
      description: 'spear phishing',
      created_at: '2025-07-16T13:39:37.601Z',
      external_id: 'CAPEC-163',
      url: null,
      entity_type: 'External-Reference',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:37.601Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:37.601Z',
      x_opencti_stix_ids: [],
      source_name: 'capec',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '754f8882-585d-470c-8765-e6b85cd2fc21',
        id: '754f8882-585d-470c-8765-e6b85cd2fc21',
        sort: [
          'relationship-meta--00cb7c91-1eb8-45c3-a42e-7ce1aeef0c0c'
        ],
        standard_id: 'relationship-meta--00cb7c91-1eb8-45c3-a42e-7ce1aeef0c0c',
        base_type: 'RELATION',
        entity_type: 'external-reference',
        internal_id: '754f8882-585d-470c-8765-e6b85cd2fc21',
        from: null,
        fromId: 'c914c155-5672-432d-9904-c7981d81caa5',
        fromRole: 'external-reference_from',
        fromName: 'Tool Stix 2.0',
        fromType: 'Tool',
        source_ref: 'tool--temporary',
        to: null,
        toId: '40cba5a9-e7a6-4c6d-b3da-d0c929159a35',
        toRole: 'external-reference_to',
        toName: 'capec (CAPEC-163)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ],
  killChainPhases: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'dd7d2257-a65e-4d74-a8fa-1472cf593aa4',
      id: 'dd7d2257-a65e-4d74-a8fa-1472cf593aa4',
      sort: [
        1752673181013
      ],
      standard_id: 'kill-chain-phase--498ccf4c-2534-5534-83cd-9a3c61a4f287',
      x_opencti_order: 0,
      internal_id: 'dd7d2257-a65e-4d74-a8fa-1472cf593aa4',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:41.013Z',
      confidence: 100,
      created_at: '2025-07-16T13:39:41.013Z',
      kill_chain_name: 'mitre-pre-attack',
      entity_type: 'Kill-Chain-Phase',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:41.013Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:41.013Z',
      phase_name: 'launch',
      x_opencti_stix_ids: [],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'abfe875b-aca8-4c3f-a34b-f2ac362e11ad',
        id: 'abfe875b-aca8-4c3f-a34b-f2ac362e11ad',
        sort: [
          'relationship-meta--1d147529-d587-4ce7-a3fe-2235ba0328f7'
        ],
        standard_id: 'relationship-meta--1d147529-d587-4ce7-a3fe-2235ba0328f7',
        base_type: 'RELATION',
        entity_type: 'kill-chain-phase',
        internal_id: 'abfe875b-aca8-4c3f-a34b-f2ac362e11ad',
        from: null,
        fromId: 'c914c155-5672-432d-9904-c7981d81caa5',
        fromRole: 'kill-chain-phase_from',
        fromName: 'Tool Stix 2.0',
        fromType: 'Tool',
        source_ref: 'tool--temporary',
        to: null,
        toId: 'dd7d2257-a65e-4d74-a8fa-1472cf593aa4',
        toRole: 'kill-chain-phase_to',
        toName: 'launch',
        toType: 'Kill-Chain-Phase',
        target_ref: 'kill-chain-phase--temporary',
        relationship_type: 'kill-chain-phase'
      }
    }
  ],
  objectMarking: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: 'c716bc3f-4b39-4911-b2ba-c972d15cff15',
      id: 'c716bc3f-4b39-4911-b2ba-c972d15cff15',
      sort: [
        1752671046674
      ],
      standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
      x_opencti_color: '#ffffff',
      x_opencti_order: 1,
      internal_id: 'c716bc3f-4b39-4911-b2ba-c972d15cff15',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      definition_type: 'PAP',
      created: '2025-07-16T13:04:06.674Z',
      confidence: 100,
      created_at: '2025-07-16T13:04:06.674Z',
      entity_type: 'Marking-Definition',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:04:06.674Z',
      creator_id: [
        '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
      ],
      modified: '2025-07-16T13:04:06.674Z',
      definition: 'PAP:CLEAR',
      x_opencti_stix_ids: [],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'b593658b-9b64-4b4b-99ee-5154ae805beb',
        id: 'b593658b-9b64-4b4b-99ee-5154ae805beb',
        sort: [
          'relationship-meta--3247b925-458e-47e3-ab09-4ffb97056257'
        ],
        standard_id: 'relationship-meta--3247b925-458e-47e3-ab09-4ffb97056257',
        base_type: 'RELATION',
        entity_type: 'object-marking',
        internal_id: 'b593658b-9b64-4b4b-99ee-5154ae805beb',
        from: null,
        fromId: 'c914c155-5672-432d-9904-c7981d81caa5',
        fromRole: 'object-marking_from',
        fromName: 'Tool Stix 2.0',
        fromType: 'Tool',
        source_ref: 'tool--temporary',
        to: null,
        toId: 'c716bc3f-4b39-4911-b2ba-c972d15cff15',
        toRole: 'object-marking_to',
        toName: 'PAP:CLEAR',
        toType: 'Marking-Definition',
        target_ref: 'marking-definition--temporary',
        relationship_type: 'object-marking'
      }
    }
  ],
  createdBy: {
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
      _id: 'c316e119-11cd-4104-895b-479bd341c9ce',
      id: 'c316e119-11cd-4104-895b-479bd341c9ce',
      sort: [
        'relationship-meta--8f8b7e68-7e33-438e-814e-04d06dea2b74'
      ],
      standard_id: 'relationship-meta--8f8b7e68-7e33-438e-814e-04d06dea2b74',
      base_type: 'RELATION',
      entity_type: 'created-by',
      internal_id: 'c316e119-11cd-4104-895b-479bd341c9ce',
      from: null,
      fromId: 'c914c155-5672-432d-9904-c7981d81caa5',
      fromRole: 'created-by_from',
      fromName: 'Tool Stix 2.0',
      fromType: 'Tool',
      source_ref: 'tool--temporary',
      to: null,
      toId: '079db495-ef69-402b-b28f-31953b770f0f',
      toRole: 'created-by_to',
      toName: 'ANSSI',
      toType: 'Organization',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '639956e1-a6b9-4aa8-bb79-55f97af280b3',
      id: '639956e1-a6b9-4aa8-bb79-55f97af280b3',
      sort: [
        1752673180222
      ],
      standard_id: 'label--66b4d95f-ba1a-54b3-b5a3-74c7fb93142b',
      color: '#1da735',
      internal_id: '639956e1-a6b9-4aa8-bb79-55f97af280b3',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:40.222Z',
      confidence: 100,
      created_at: '2025-07-16T13:39:40.222Z',
      entity_type: 'Label',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:40.222Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:40.222Z',
      x_opencti_stix_ids: [],
      value: 'ryuk',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '6d685e9b-c9dd-4481-9d26-7de91cb38fef',
        id: '6d685e9b-c9dd-4481-9d26-7de91cb38fef',
        sort: [
          'relationship-meta--a250b7a9-dcc0-4e2a-bdc0-57dff3836b10'
        ],
        standard_id: 'relationship-meta--a250b7a9-dcc0-4e2a-bdc0-57dff3836b10',
        base_type: 'RELATION',
        entity_type: 'object-label',
        internal_id: '6d685e9b-c9dd-4481-9d26-7de91cb38fef',
        from: null,
        fromId: 'c914c155-5672-432d-9904-c7981d81caa5',
        fromRole: 'object-label_from',
        fromName: 'Tool Stix 2.0',
        fromType: 'Tool',
        source_ref: 'tool--temporary',
        to: null,
        toId: '639956e1-a6b9-4aa8-bb79-55f97af280b3',
        toRole: 'object-label_to',
        toName: 'ryuk',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreEntity;
export const EXPECTED_TOOL = {
  id: 'tool--a8bdbff3-16b4-5cd2-b112-ee7a7b1f359c',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-08-01T15:23:49.755Z',
  modified: '2025-08-01T15:29:11.399Z',
  name: 'Tool Stix 2.0',
  description: 'description',
  tool_types: [
    'denial-of-service'
  ],
  tool_version: '2',
  labels: [
    'ryuk'
  ],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-pre-attack',
      phase_name: 'launch',
      x_opencti_order: 0
    }
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: 'c914c155-5672-432d-9904-c7981d81caa5',
  x_opencti_type: 'Tool',
  type: 'tool',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34'
  ],
  x_opencti_files: [],
  x_opencti_granted_refs: [],
};
