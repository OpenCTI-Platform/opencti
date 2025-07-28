import type { StoreRelation } from '../../../../src/types/store';

export const SIGHTING_INSTANCE = {
  _index: 'opencti_stix_sighting_relationships-000001',
  _id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  sort: [
    1753946816885
  ],
  standard_id: 'sighting--22799cbd-e9b5-5b7c-8733-5c2a5cc49ebe',
  attribute_count: 1,
  first_seen: '2025-07-30T22:00:00.000Z',
  internal_id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  last_seen: '2025-07-30T22:00:00.000Z',
  parent_types: [
    'basic-relationship',
    'stix-relationship'
  ],
  i_attributes: [
    {
      updated_at: '2025-07-31T07:27:17.404Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectOrganization'
    },
    {
      updated_at: '2025-07-31T07:27:23.564Z',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      confidence: 100,
      name: 'objectLabel'
    }
  ],
  created: '2025-07-31T07:26:56.885Z',
  confidence: 100,
  created_at: '2025-07-31T07:26:56.885Z',
  description: 'descri',
  revoked: false,
  entity_type: 'stix-sighting-relationship',
  base_type: 'RELATION',
  relationship_type: 'stix-sighting-relationship',
  updated_at: '2025-07-31T07:28:43.240Z',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  x_opencti_negative: true,
  modified: '2025-07-31T07:28:43.240Z',
  x_opencti_stix_ids: [],
  lang: 'en',
  from: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
    id: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
    sort: [
      1752673180801
    ],
    standard_id: 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Core-Object',
      'Stix-Domain-Object'
    ],
    pattern: "[domain-name:value = 'www.one-clap.jp']",
    description: 'download location',
    valid_from: '2016-09-09T05:58:02.000Z',
    created_at: '2025-07-16T13:39:40.801Z',
    revoked: true,
    base_type: 'ENTITY',
    updated_at: '2025-07-16T13:39:40.816Z',
    modified: '2025-07-16T13:39:40.816Z',
    lang: 'en',
    x_opencti_score: 50,
    x_opencti_workflow_id: null,
    pattern_type: 'stix',
    internal_id: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
    created: '2020-02-25T22:25:59.714Z',
    confidence: 100,
    pattern_version: null,
    x_opencti_main_observable_type: 'Unknown',
    x_mitre_platforms: null,
    valid_until: '2017-09-09T05:58:02.000Z',
    entity_type: 'Indicator',
    indicator_types: null,
    name: 'www.one-clap.jp',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    x_opencti_detection: false,
    x_opencti_stix_ids: [
      'indicator--51640662-9c78-4402-932f-1d4531624723'
    ],
    'rel_created-by.internal_id.keyword': [
      '47cffe73-dcad-4830-884d-8d10f66780c5'
    ],
    'rel_object-label.internal_id.keyword': [
      '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9'
    ],
    'rel_object-marking.internal_id.keyword': [
      'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1'
    ],
    'created-by': '47cffe73-dcad-4830-884d-8d10f66780c5',
    'object-label': [
      '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9'
    ],
    'object-marking': [
      'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1'
    ],
    createdBy: {
      _index: 'opencti_stix_domain_objects-000001',
      _id: '47cffe73-dcad-4830-884d-8d10f66780c5',
      id: '47cffe73-dcad-4830-884d-8d10f66780c5',
      sort: [
        1752673178421
      ],
      standard_id: 'identity--4f347cc9-4658-59ee-9707-134f434f9d1c',
      identity_class: 'organization',
      x_opencti_organization_type: null,
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
      created_at: '2025-07-16T13:39:38.421Z',
      x_opencti_aliases: [
        'Computer Incident',
        'Incident'
      ],
      revoked: false,
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:38.437Z',
      modified: '2025-07-16T13:39:38.437Z',
      i_aliases_ids: [
        'identity--d33c9d53-d0b0-5c3c-9b3c-d4bc5bcf57e5',
        'identity--07115639-5968-5607-8d2c-b38d3392e80c'
      ],
      lang: 'en',
      x_opencti_workflow_id: null,
      internal_id: '47cffe73-dcad-4830-884d-8d10f66780c5',
      x_opencti_reliability: 'B - Usually reliable',
      created: '2020-02-25T22:23:20.648Z',
      confidence: 100,
      entity_type: 'Organization',
      name: 'CIRCL',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      x_opencti_stix_ids: [
        'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132'
      ],
      'rel_object-label.internal_id.keyword': [
        '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
      ],
      'object-label': [
        '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
      ],
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: 'dc34e7d9-257a-42c0-9695-03ae37986184',
        id: 'dc34e7d9-257a-42c0-9695-03ae37986184',
        sort: [
          'relationship-meta--19e9ae66-7301-40e9-8bc6-5b28fcfe55e6'
        ],
        standard_id: 'relationship-meta--19e9ae66-7301-40e9-8bc6-5b28fcfe55e6',
        base_type: 'RELATION',
        entity_type: 'created-by',
        internal_id: 'dc34e7d9-257a-42c0-9695-03ae37986184',
        from: null,
        fromId: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
        fromRole: 'created-by_from',
        fromName: 'www.one-clap.jp',
        fromType: 'Indicator',
        source_ref: 'indicator--temporary',
        to: null,
        toId: '47cffe73-dcad-4830-884d-8d10f66780c5',
        toRole: 'created-by_to',
        toName: 'CIRCL',
        toType: 'Organization',
        target_ref: 'identity--temporary',
        relationship_type: 'created-by'
      }
    },
    objectLabel: [
      {
        _index: 'opencti_stix_meta_objects-000001',
        _id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
        id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
        sort: [
          1752673180675
        ],
        standard_id: 'label--46fcca3d-554a-5d0a-b76c-858d3aa2ddce',
        color: '#0fbe8f',
        internal_id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Meta-Object'
        ],
        created: '2025-07-16T13:39:40.675Z',
        confidence: 100,
        created_at: '2025-07-16T13:39:40.675Z',
        entity_type: 'Label',
        base_type: 'ENTITY',
        updated_at: '2025-07-16T13:39:40.675Z',
        creator_id: [
          '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        ],
        modified: '2025-07-16T13:39:40.675Z',
        x_opencti_stix_ids: [],
        value: 'indicator',
        i_relation: {
          _index: 'opencti_stix_meta_relationships-000001',
          _id: 'c465d423-7c5d-4a86-bbd2-9535d97333ac',
          id: 'c465d423-7c5d-4a86-bbd2-9535d97333ac',
          sort: [
            'relationship-meta--6bf7f892-18d3-4add-b3ca-bc0e0fa0ad17'
          ],
          standard_id: 'relationship-meta--6bf7f892-18d3-4add-b3ca-bc0e0fa0ad17',
          base_type: 'RELATION',
          entity_type: 'object-label',
          internal_id: 'c465d423-7c5d-4a86-bbd2-9535d97333ac',
          from: null,
          fromId: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
          fromRole: 'object-label_from',
          fromName: 'www.one-clap.jp',
          fromType: 'Indicator',
          source_ref: 'indicator--temporary',
          to: null,
          toId: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
          toRole: 'object-label_to',
          toName: 'indicator',
          toType: 'Label',
          target_ref: 'label--temporary',
          relationship_type: 'object-label'
        }
      }
    ],
    objectMarking: [
      {
        _index: 'opencti_stix_meta_objects-000001',
        _id: 'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1',
        id: 'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1',
        sort: [
          1752671044567
        ],
        standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        x_opencti_color: '#ffffff',
        x_opencti_order: 1,
        internal_id: 'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1',
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Meta-Object'
        ],
        definition_type: 'TLP',
        i_attributes: [
          {
            updated_at: '2025-07-16T13:39:38.482Z',
            user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
            confidence: 100,
            name: 'creator_id'
          }
        ],
        created: '2025-07-16T13:04:04.567Z',
        confidence: 100,
        created_at: '2025-07-16T13:04:04.567Z',
        entity_type: 'Marking-Definition',
        base_type: 'ENTITY',
        updated_at: '2025-07-16T13:39:38.481Z',
        creator_id: [
          '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
          '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        ],
        modified: '2025-07-16T13:39:38.481Z',
        definition: 'TLP:CLEAR',
        x_opencti_stix_ids: [],
        i_relation: {
          _index: 'opencti_stix_meta_relationships-000001',
          _id: '084d3dc8-048b-4053-ac6b-fad7e2565d10',
          id: '084d3dc8-048b-4053-ac6b-fad7e2565d10',
          sort: [
            'relationship-meta--ca518d78-8f78-45c1-92e4-e935ea71e0be'
          ],
          standard_id: 'relationship-meta--ca518d78-8f78-45c1-92e4-e935ea71e0be',
          base_type: 'RELATION',
          entity_type: 'object-marking',
          internal_id: '084d3dc8-048b-4053-ac6b-fad7e2565d10',
          from: null,
          fromId: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
          fromRole: 'object-marking_from',
          fromName: 'www.one-clap.jp',
          fromType: 'Indicator',
          source_ref: 'indicator--temporary',
          to: null,
          toId: 'e5532fc1-a41d-4f68-bc6c-66c4a534b2d1',
          toRole: 'object-marking_to',
          toName: 'TLP:CLEAR',
          toType: 'Marking-Definition',
          target_ref: 'marking-definition--temporary',
          relationship_type: 'object-marking'
        }
      }
    ]
  },
  fromId: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
  fromRole: 'stix-sighting-relationship_from',
  fromName: 'www.one-clap.jp',
  fromType: 'Indicator',
  source_ref: 'indicator--temporary',
  to: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '47cffe73-dcad-4830-884d-8d10f66780c5',
    id: '47cffe73-dcad-4830-884d-8d10f66780c5',
    sort: [
      1752673178421
    ],
    standard_id: 'identity--4f347cc9-4658-59ee-9707-134f434f9d1c',
    identity_class: 'organization',
    x_opencti_organization_type: null,
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
    created_at: '2025-07-16T13:39:38.421Z',
    x_opencti_aliases: [
      'Computer Incident',
      'Incident'
    ],
    revoked: false,
    base_type: 'ENTITY',
    updated_at: '2025-07-16T13:39:38.437Z',
    modified: '2025-07-16T13:39:38.437Z',
    i_aliases_ids: [
      'identity--d33c9d53-d0b0-5c3c-9b3c-d4bc5bcf57e5',
      'identity--07115639-5968-5607-8d2c-b38d3392e80c'
    ],
    lang: 'en',
    x_opencti_workflow_id: null,
    internal_id: '47cffe73-dcad-4830-884d-8d10f66780c5',
    x_opencti_reliability: 'B - Usually reliable',
    created: '2020-02-25T22:23:20.648Z',
    confidence: 100,
    entity_type: 'Organization',
    name: 'CIRCL',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    x_opencti_stix_ids: [
      'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132'
    ],
    'rel_object-label.internal_id.keyword': [
      '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
    ],
    'object-label': [
      '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
    ],
    objectLabel: [
      {
        _index: 'opencti_stix_meta_objects-000001',
        _id: '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9',
        id: '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9',
        sort: [
          1752673177401
        ],
        standard_id: 'label--355f76bb-be36-58dd-bdc9-90a75529df85',
        color: '#be70e8',
        internal_id: '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9',
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Meta-Object'
        ],
        created: '2025-07-16T13:39:37.401Z',
        confidence: 100,
        created_at: '2025-07-16T13:39:37.401Z',
        entity_type: 'Label',
        base_type: 'ENTITY',
        updated_at: '2025-07-16T13:39:37.401Z',
        creator_id: [
          '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        ],
        modified: '2025-07-16T13:39:37.401Z',
        x_opencti_stix_ids: [],
        value: 'identity',
        i_relation: {
          _index: 'opencti_stix_meta_relationships-000001',
          _id: '431a5703-0104-43c6-84bb-ecfee964eb39',
          id: '431a5703-0104-43c6-84bb-ecfee964eb39',
          sort: [
            'relationship-meta--00e598bf-667a-44a5-bae0-14d421c335bb'
          ],
          standard_id: 'relationship-meta--00e598bf-667a-44a5-bae0-14d421c335bb',
          base_type: 'RELATION',
          entity_type: 'object-label',
          internal_id: '431a5703-0104-43c6-84bb-ecfee964eb39',
          from: null,
          fromId: '47cffe73-dcad-4830-884d-8d10f66780c5',
          fromRole: 'object-label_from',
          fromName: 'CIRCL',
          fromType: 'Organization',
          source_ref: 'identity--temporary',
          to: null,
          toId: '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9',
          toRole: 'object-label_to',
          toName: 'identity',
          toType: 'Label',
          target_ref: 'label--temporary',
          relationship_type: 'object-label'
        }
      }
    ]
  },
  toId: '47cffe73-dcad-4830-884d-8d10f66780c5',
  toRole: 'stix-sighting-relationship_to',
  toName: 'CIRCL',
  toType: 'Organization',
  target_ref: 'identity--temporary',
  'rel_created-by.internal_id.keyword': [
    '9006ee76-e229-4ee9-a61a-9a4473606d9e'
  ],
  'rel_object-label.internal_id.keyword': [
    '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9'
  ],
  'rel_granted.internal_id.keyword': [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'rel_object-marking.internal_id.keyword': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
  ],
  'created-by': '9006ee76-e229-4ee9-a61a-9a4473606d9e',
  'object-label': [
    '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9'
  ],
  granted: [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'object-marking': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
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
        _id: 'a8b5415a-ec96-4fab-913f-acedf14e9fb9',
        id: 'a8b5415a-ec96-4fab-913f-acedf14e9fb9',
        sort: [
          'relationship-meta--11924f05-06a7-4f52-821b-98c7f5a90a61'
        ],
        standard_id: 'relationship-meta--11924f05-06a7-4f52-821b-98c7f5a90a61',
        base_type: 'RELATION',
        entity_type: 'granted',
        internal_id: 'a8b5415a-ec96-4fab-913f-acedf14e9fb9',
        from: null,
        fromId: '11cad6c5-98f1-4491-899a-15b7789e1492',
        fromRole: 'granted_from',
        fromName: 'www.one-clap.jp ➡️ CIRCL',
        fromType: 'stix-sighting-relationship',
        source_ref: 'sighting--temporary',
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
  createdBy: {
    _index: 'opencti_stix_domain_objects-000001',
    _id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
    id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
    sort: [
      1752673179321
    ],
    standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
    identity_class: 'individual',
    x_opencti_lastname: null,
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
    created_at: '2025-07-16T13:39:39.321Z',
    x_opencti_firstname: null,
    x_opencti_aliases: null,
    revoked: false,
    base_type: 'ENTITY',
    updated_at: '2025-07-16T13:39:39.333Z',
    modified: '2025-07-16T13:39:39.333Z',
    i_aliases_ids: [],
    lang: 'en',
    x_opencti_workflow_id: null,
    internal_id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
    x_opencti_reliability: null,
    created: '2020-03-27T08:39:45.676Z',
    confidence: 100,
    entity_type: 'Individual',
    name: 'John Doe',
    creator_id: [
      '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
    ],
    x_opencti_stix_ids: [
      'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f'
    ],
    'rel_object-label.internal_id.keyword': [
      '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
    ],
    'object-label': [
      '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
    ],
    i_relation: {
      _index: 'opencti_stix_meta_relationships-000001',
      _id: '82d2af8d-5a8d-40d8-8ddd-69f7624aa2b4',
      id: '82d2af8d-5a8d-40d8-8ddd-69f7624aa2b4',
      sort: [
        'relationship-meta--47df10f0-c84d-4d28-8506-70765aaa719f'
      ],
      standard_id: 'relationship-meta--47df10f0-c84d-4d28-8506-70765aaa719f',
      base_type: 'RELATION',
      entity_type: 'created-by',
      internal_id: '82d2af8d-5a8d-40d8-8ddd-69f7624aa2b4',
      from: null,
      fromId: '11cad6c5-98f1-4491-899a-15b7789e1492',
      fromRole: 'created-by_from',
      fromName: 'undefined ➡️ undefined',
      fromType: 'stix-sighting-relationship',
      source_ref: 'sighting--temporary',
      to: null,
      toId: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
      toRole: 'created-by_to',
      toName: 'John Doe',
      toType: 'Individual',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  },
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
        _id: '7e42afa9-25aa-4a27-a169-69ad11d1d1a4',
        id: '7e42afa9-25aa-4a27-a169-69ad11d1d1a4',
        sort: [
          'relationship-meta--5612b228-d5bb-4e2f-a12b-dd97c78c7f0c'
        ],
        standard_id: 'relationship-meta--5612b228-d5bb-4e2f-a12b-dd97c78c7f0c',
        base_type: 'RELATION',
        entity_type: 'object-marking',
        internal_id: '7e42afa9-25aa-4a27-a169-69ad11d1d1a4',
        from: null,
        fromId: '11cad6c5-98f1-4491-899a-15b7789e1492',
        fromRole: 'object-marking_from',
        fromName: 'undefined ➡️ undefined',
        fromType: 'stix-sighting-relationship',
        source_ref: 'sighting--temporary',
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
  'external-reference': [
    '2e114681-68ec-4111-84b0-7d8186b36c1f'
  ],
  externalReferences: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '2e114681-68ec-4111-84b0-7d8186b36c1f',
      id: '2e114681-68ec-4111-84b0-7d8186b36c1f',
      sort: [
        1752673180775
      ],
      standard_id: 'external-reference--17c67347-99df-548d-8389-1238c9e04a6c',
      internal_id: '2e114681-68ec-4111-84b0-7d8186b36c1f',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:40.775Z',
      confidence: 100,
      description: null,
      created_at: '2025-07-16T13:39:40.775Z',
      external_id: 'CVE-2012-0158',
      url: null,
      entity_type: 'External-Reference',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:40.775Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:40.775Z',
      x_opencti_stix_ids: [],
      source_name: 'cve',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '96547fcf-eff6-4f71-a0f0-43a59e43bf66',
        id: '96547fcf-eff6-4f71-a0f0-43a59e43bf66',
        sort: [
          'relationship-meta--63e39174-217e-4939-bf47-525ecce53fb6'
        ],
        standard_id: 'relationship-meta--63e39174-217e-4939-bf47-525ecce53fb6',
        base_type: 'RELATION',
        entity_type: 'external-reference',
        internal_id: '96547fcf-eff6-4f71-a0f0-43a59e43bf66',
        from: null,
        fromId: '11cad6c5-98f1-4491-899a-15b7789e1492',
        fromRole: 'external-reference_from',
        fromName: 'undefined ➡️ undefined',
        fromType: 'stix-sighting-relationship',
        source_ref: 'sighting--temporary',
        to: null,
        toId: '2e114681-68ec-4111-84b0-7d8186b36c1f',
        toRole: 'external-reference_to',
        toName: 'cve (CVE-2012-0158)',
        toType: 'External-Reference',
        target_ref: 'external-reference--temporary',
        relationship_type: 'external-reference'
      }
    }
  ],
  objectLabel: [
    {
      _index: 'opencti_stix_meta_objects-000001',
      _id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
      id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
      sort: [
        1752673180675
      ],
      standard_id: 'label--46fcca3d-554a-5d0a-b76c-858d3aa2ddce',
      color: '#0fbe8f',
      internal_id: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
      parent_types: [
        'Basic-Object',
        'Stix-Object',
        'Stix-Meta-Object'
      ],
      created: '2025-07-16T13:39:40.675Z',
      confidence: 100,
      created_at: '2025-07-16T13:39:40.675Z',
      entity_type: 'Label',
      base_type: 'ENTITY',
      updated_at: '2025-07-16T13:39:40.675Z',
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      modified: '2025-07-16T13:39:40.675Z',
      x_opencti_stix_ids: [],
      value: 'indicator',
      i_relation: {
        _index: 'opencti_stix_meta_relationships-000001',
        _id: '5b4190a5-c0f7-422b-aace-29b664db1fe7',
        id: '5b4190a5-c0f7-422b-aace-29b664db1fe7',
        sort: [
          'relationship-meta--d377a574-e57f-415e-a92c-a296c5d69147'
        ],
        standard_id: 'relationship-meta--d377a574-e57f-415e-a92c-a296c5d69147',
        base_type: 'RELATION',
        entity_type: 'object-label',
        internal_id: '5b4190a5-c0f7-422b-aace-29b664db1fe7',
        from: null,
        fromId: '11cad6c5-98f1-4491-899a-15b7789e1492',
        fromRole: 'object-label_from',
        fromName: 'www.one-clap.jp ➡️ CIRCL',
        fromType: 'stix-sighting-relationship',
        source_ref: 'sighting--temporary',
        to: null,
        toId: '97bd20d3-d9a4-4c5a-9768-a6e0f1ef6fa9',
        toRole: 'object-label_to',
        toName: 'indicator',
        toType: 'Label',
        target_ref: 'label--temporary',
        relationship_type: 'object-label'
      }
    }
  ]
} as unknown as StoreRelation;

export const EXPECTED_SIGHTING = {
  id: 'sighting--22799cbd-e9b5-5b7c-8733-5c2a5cc49ebe',
  spec_version: '2.0',
  revoked: false,
  description: 'descri',
  first_seen: '2025-07-30T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  x_opencti_negative: true,
  created: '2025-07-31T07:26:56.885Z',
  modified: '2025-07-31T07:28:43.240Z',
  confidence: 100,
  labels: [
    'indicator'
  ],
  external_references: [
    {
      source_name: 'cve',
      external_id: 'CVE-2012-0158'
    }
  ],
  x_opencti_id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  x_opencti_type: 'stix-sighting-relationship',
  type: 'sighting',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  x_opencti_granted_refs: [
    'identity--18fe5225-fee1-5627-ad3e-20c14435b024'
  ],
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
  ],
  count: 1,
  sighting_of_ref: 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752',
  where_sighted_refs: [
    'identity--4f347cc9-4658-59ee-9707-134f434f9d1c'
  ],
  x_opencti_files: [],
};
