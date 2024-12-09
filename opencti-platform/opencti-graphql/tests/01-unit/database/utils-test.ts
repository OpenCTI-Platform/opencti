import { describe, expect, it } from 'vitest';
import { extractObjectsRestrictionsFromInputs } from '../../../src/database/utils';

const inputs = [
  {
    key: 'objects',
    operation: 'add',
    value: [
      {
        _id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        _index: 'opencti_stix_domain_objects-000001',
        aliases: [],
        base_type: 'ENTITY',
        confidence: 100,
        created: '2024  -11-08T10:30:44.343Z',
        'created-by': 'bc9fe33d-e694-4604-abc1-82f2e99cd00a',
        created_at: '2024-12-02T13:55:39.981Z',
        creator_id: [
          '549e078a-41df-43aa-8e0f-ba961b16d0c8'
        ],
        description: '',
        entity_type: 'Intrusion-Set',
        'external-reference': [],
        first_seen: '1970-01-01T00:00:00.000Z',
        goals: ['Military Advantage'],
        i_aliases_ids: [],
        id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        internal_id: '4c688965-fd97-40ea-9af0-967030eb06a5',
        lang: 'en',
        last_seen: '5138-11-16T09:46:40.000Z',
        modified: '2024-12-02T13:55:40.064Z',
        name: 'AP  T29',
        'object-label': [
          'debcc53e-9515-4107-bbdc-8eb8084f7527'
        ],
        'object-marking': [
          'fa7fa933-7b65-463f-ac5e-aa33b2a36ce8',
          '056276ff-26dc-4774-a439-a36253a96939'
        ],
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Core-Object',
          'Stix-  Domain-Object'
        ],
        primary_motivation: 'Espionage',
        'rel_created-by.internal_id': [
          'bc9fe33d-e694-4604-abc1-82f2e99cd00a'
        ],
        'rel_external-reference.internal_id': [],
        'rel_object-labe  l.internal_id': [
          'debcc53e-9515-4107-bbdc-8eb8084f7527'
        ],
        'rel_object-marking.internal_id': [
          'fa7fa933-7b65-463f-ac5e-aa33b2a36ce8',
          '056276ff-26dc-4774-a439-a36253a96939'
        ],
        resource_level: null,
        revoked: false,
        'secondary_motivation  s': [
          'Military/Security/Diplomatic',
          'Ethnic/nationalist',
          'Ideological/Religious'
        ],
        sort: [
          1733147739981
        ],
        standard_id: 'intrusion-set--36319194-19e1-50ac-9163-778b56a1bf12',
        updated_at: '2024-12-02T13:55:40.064Z',
        x_opencti_stix_ids: [],
        x_opencti_workflow_id: null
      }
    ]
  }
];

const relInputs = [
  {
    key: 'objects',
    operation: 'add',
    value: [
      {
        _id: '23c0c086-afee-45e5-b276-872948997816',
        _index: 'opencti_stix_core_relationships-000001',
        base_type: 'RELATION',
        confidence: 100,
        created: '2024-12-0  6T08:41:59.270Z',
        created_at: '2024-12-06T08:41:59.270Z',
        creator_id: [
          '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        ],
        description: '',
        entity_type: 'related-to',
        from: null,
        fromId: 'fd3259cb-f219-4cd6-85fe-0df16ffef185',
        fromName: 'AlienVault',
        fromRole: 'related-to_from',
        fromType: 'Organization',
        id: '23c0c086-afee-45e5-b276-872948997816',
        internal_id: '23c0c086-afee-45e5-b276-872948997816',
        lang: 'en',
        modified: '2024-12-06T08:41:59.290Z',
        'object-marking': [
          'eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'
        ],
        parent_types: [
          'basic-relationship',
          'stix-relationship',
          'stix-core-relationship'
        ],
        'rel_object-marking.internal_id': [
          'eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'
        ],
        relationship_type: 'related-to',
        revoked: false,
        sort: [
          1733474519270
        ],
        source_ref: 'identity--temporary',
        standard_id: 'relationship--54af1a95-b0e8-53d6-8c0c-074f57e9d58c',
        start_time: '2024-12-06T08:40:55.000Z',
        stop_time: '2024-12-06T08:41:55.000Z',
        'ta  rget_ref': 'malware--temporary',
        to: null,
        toId: 'd9162b45-55dd-403b-906b-a16edf74ebff',
        toName: 'HAMMERTOSS',
        toRole: 'related-to_to',
        toType: 'Malware',
        updated_at: '2024-12-06T08:41:59.290Z',
        x_opencti_stix_ids: []
      }
    ]
  }
];

describe('extractObjectsRestrictionsFromInputs testing', () => {
  it('should add inputs object-marking in stream when adding entity to a report', () => {
    const relatedRestrictions = extractObjectsRestrictionsFromInputs(inputs);
    const expected = { markings: ['fa7fa933-7b65-463f-ac5e-aa33b2a36ce8', '056276ff-26dc-4774-a439-a36253a96939'] };
    expect(relatedRestrictions).toEqual(expected);
  });
  it('should add inputs object-marking in stream when adding relationship to a report', () => {
    const relatedRestrictions = extractObjectsRestrictionsFromInputs(relInputs);
    const expected = { markings: ['eaccd139-ec2e-48d9-b2ef-a17ba6e7e938'] };
    expect(relatedRestrictions).toEqual(expected);
  });
});
