import type { StoreEntity } from '../../../../src/types/store';

export const INSTANCE_CHANNEL = {
  _index: 'opencti_stix_domain_objects-000001',
  _id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  sort: [
    1754062441690
  ],
  standard_id: 'channel--6e66b6f7-f60b-50d9-8d6c-6686192695d6',
  internal_id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  parent_types: [
    'Basic-Object',
    'Stix-Object',
    'Stix-Core-Object',
    'Stix-Domain-Object'
  ],
  created: '2025-08-01T15:34:01.690Z',
  confidence: 100,
  description: 'description',
  created_at: '2025-08-01T15:34:01.690Z',
  revoked: false,
  entity_type: 'Channel',
  base_type: 'ENTITY',
  updated_at: '2025-08-01T15:36:28.567Z',
  name: 'Channel Stix 2.0',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  channel_types: [
    'Facebook'
  ],
  modified: '2025-08-01T15:36:28.567Z',
  i_aliases_ids: [],
  x_opencti_stix_ids: [],
  lang: 'en',
  'rel_created-by.internal_id.keyword': [
    '079db495-ef69-402b-b28f-31953b770f0f'
  ],
  'rel_object-label.internal_id.keyword': [
    'ad9a877b-d550-492f-a39e-3be894b16296'
  ],
  'rel_object-marking.internal_id.keyword': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
  ],
  'created-by': '079db495-ef69-402b-b28f-31953b770f0f',
  'object-label': [
    'ad9a877b-d550-492f-a39e-3be894b16296'
  ],
  'object-marking': [
    '1af26c84-a670-4ea4-b420-9c9639519142'
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
        _id: 'dc2194c4-f133-4712-864a-a247c9562632',
        id: 'dc2194c4-f133-4712-864a-a247c9562632',
        sort: [
          'relationship-meta--10717094-7d3a-4fbf-93be-2545e32342eb'
        ],
        standard_id: 'relationship-meta--10717094-7d3a-4fbf-93be-2545e32342eb',
        base_type: 'RELATION',
        entity_type: 'object-marking',
        internal_id: 'dc2194c4-f133-4712-864a-a247c9562632',
        from: null,
        fromId: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
        fromRole: 'object-marking_from',
        fromName: 'Channel Stix 2.0',
        fromType: 'Channel',
        source_ref: 'channel--temporary',
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
        _id: '4419e9c6-4d83-47c1-b26b-6d969e7c2e72',
        id: '4419e9c6-4d83-47c1-b26b-6d969e7c2e72',
        sort: [
          'relationship-meta--90809594-51ca-4557-8e9c-c35f2cebf625'
        ],
        standard_id: 'relationship-meta--90809594-51ca-4557-8e9c-c35f2cebf625',
        base_type: 'RELATION',
        entity_type: 'external-reference',
        internal_id: '4419e9c6-4d83-47c1-b26b-6d969e7c2e72',
        from: null,
        fromId: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
        fromRole: 'external-reference_from',
        fromName: 'Channel Stix 2.0',
        fromType: 'Channel',
        source_ref: 'channel--temporary',
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
        _id: 'fcbc2a0d-74a0-4a50-8b71-ae8b7dc5a908',
        id: 'fcbc2a0d-74a0-4a50-8b71-ae8b7dc5a908',
        sort: [
          'relationship-meta--af9faa45-0c32-450a-bfe9-eb81513caf16'
        ],
        standard_id: 'relationship-meta--af9faa45-0c32-450a-bfe9-eb81513caf16',
        base_type: 'RELATION',
        entity_type: 'object-label',
        internal_id: 'fcbc2a0d-74a0-4a50-8b71-ae8b7dc5a908',
        from: null,
        fromId: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
        fromRole: 'object-label_from',
        fromName: 'Channel Stix 2.0',
        fromType: 'Channel',
        source_ref: 'channel--temporary',
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
      _id: '29e9c84d-2b04-46ef-b70e-c9dc2926ece4',
      id: '29e9c84d-2b04-46ef-b70e-c9dc2926ece4',
      sort: [
        'relationship-meta--d9162695-255b-4295-b7db-49f6e7a8f05d'
      ],
      standard_id: 'relationship-meta--d9162695-255b-4295-b7db-49f6e7a8f05d',
      base_type: 'RELATION',
      entity_type: 'created-by',
      internal_id: '29e9c84d-2b04-46ef-b70e-c9dc2926ece4',
      from: null,
      fromId: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
      fromRole: 'created-by_from',
      fromName: 'Channel Stix 2.0',
      fromType: 'Channel',
      source_ref: 'channel--temporary',
      to: null,
      toId: '079db495-ef69-402b-b28f-31953b770f0f',
      toRole: 'created-by_to',
      toName: 'ANSSI',
      toType: 'Organization',
      target_ref: 'identity--temporary',
      relationship_type: 'created-by'
    }
  }
} as unknown as StoreEntity;

export const EXPECTED_CHANNEL = {
  id: 'channel--6e66b6f7-f60b-50d9-8d6c-6686192695d6',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-08-01T15:34:01.690Z',
  modified: '2025-08-01T15:36:28.567Z',
  name: 'Channel Stix 2.0',
  description: 'description',
  channel_types: [
    'Facebook'
  ],
  labels: [
    'covid-19'
  ],
  external_references: [
    {
      source_name: 'capec',
      description: 'spear phishing',
      external_id: 'CAPEC-163'
    }
  ],
  x_opencti_id: 'b9a8e4f5-9cae-4df6-a429-f11ab0cc085b',
  x_opencti_type: 'Channel',
  type: 'channel',
  created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
  ],
};
