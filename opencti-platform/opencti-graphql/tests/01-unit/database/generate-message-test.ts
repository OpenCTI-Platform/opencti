import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { generateUpdatePatchMessage } from '../../../src/database/generate-message';

describe('generateUpdatePatchMessage tests', () => {
  it('should generate message for simple field update', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'description',
            value: [
              'updated'
            ],
            previous: [
              'initial'
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `initial` with `updated` in `Description`');
  });
  it('should generate message for simple field update if no previous value', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'description',
            value: [
              'initial'
            ],
            previous: []
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `nothing` with `initial` in `Description`');
  });
  it('should generate message for simple field update if no value', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'description',
            value: [],
            previous: ['initial']
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `initial` with `nothing` in `Description`');
  });
  it('should generate message for simple field update with multiple values', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'description',
            value: ['updated1', 'updated2', 'updated3', 'updated4'],
            previous: ['initial1', 'initial2', 'initial3', 'initial4']
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `initial1, initial2, initial3` with `updated1, updated2, updated3` in `Description` and 1 more items');
  });
  it('should generate message for field update with multiple operations', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'description',
            value: ['updated description'],
            previous: ['initial description']
          },
          {
            key: 'name',
            value: ['updated name'],
            previous: ['initial name']
          },

        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `initial description` with `updated description` in `Description` - `initial name` with `updated name` in `Name`');
  });
  it.skip('should generate message for field update with restricted members', () => {
    const data = {
      creators: [],
      members: [
        {
          internal_id: 'member-id',
          name: 'Member Name'
        }
      ]
    };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'restricted_members',
            operation: 'replace',
            previous: [{
              access_right: 'admin',
              id: 'user1'
            }],
            value: [{
              access_right: 'admin',
              id: 'user1'
            },
            {
              access_right: 'edit',
              id: 'user2'
            }
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(message).toEqual('replaces `user1` with `user2 (edit)` in `Authorized Members`');
  });
  it('should generate message for field update with creators', () => {
    const data = {
      creators: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
      members: []
    };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'createdBy',
            previous: [
              {
                _id: '47cffe73-dcad-4830-884d-8d10f66780c5',
                _index: 'opencti_stix_domain_objects-000001',
                base_type: 'ENTITY',
                confidence: 100,
                created: '2020-02-25T22:23:20.648Z',
                created_at: '2025-07-16T13:39:38.421Z',
                creator_id: [
                  '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
                ],
                entity_type: 'Organization',
                i_aliases_ids: [
                  'identity--d33c9d53-d0b0-5c3c-9b3c-d4bc5bcf57e5',
                  'identity--07115639-5968-5607-8d2c-b38d3392e80c'
                ],
                i_relation: {
                  _id: 'bbbca5b6-d2ca-4d0d-b6ee-1d53c4329c5c',
                  _index: 'opencti_stix_meta_relationships-000001',
                  base_type: 'RELATION',
                  entity_type: 'created-by',
                  fromId: '8cbd42d1-6c2d-4b4a-8ad8-5e01d91638b9',
                  fromName: 'bug log',
                  fromRole: 'created-by_from',
                  fromType: 'Malware',
                  id: 'bbbca5b6-d2ca-4d0d-b6ee-1d53c4329c5c',
                  internal_id: 'bbbca5b6-d2ca-4d0d-b6ee-1d53c4329c5c',
                  relationship_type: 'created-by',
                  sort: [
                    'relationship-meta--aca930b8-6b1d-4662-b2a2-1f8a72f6b99d'
                  ],
                  source_ref: 'malware--temporary',
                  standard_id: 'relationship-meta--aca930b8-6b1d-4662-b2a2-1f8a72f6b99d',
                  target_ref: 'identity--temporary',
                  toId: '47cffe73-dcad-4830-884d-8d10f66780c5',
                  toName: 'CIRCL',
                  toRole: 'created-by_to',
                  toType: 'Organization'
                },
                id: '47cffe73-dcad-4830-884d-8d10f66780c5',
                identity_class: 'organization',
                internal_id: '47cffe73-dcad-4830-884d-8d10f66780c5',
                lang: 'en',
                modified: '2025-07-16T13:39:38.437Z',
                name: 'CIRCL',
                'object-label': [
                  '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
                ],
                parent_types: [
                  'Basic-Object',
                  'Stix-Object',
                  'Stix-Core-Object',
                  'Stix-Domain-Object',
                  'Identity'
                ],
                'participate-to': [
                  '51c085a6-612a-463b-9575-27513bf85d99',
                  '657af4d1-8f8c-4c5d-ad50-b41648bebb33'
                ],
                'rel_object-label.internal_id.keyword': [
                  '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
                ],
                'rel_participate-to.internal_id.keyword': [
                  '51c085a6-612a-463b-9575-27513bf85d99',
                  '657af4d1-8f8c-4c5d-ad50-b41648bebb33'
                ],
                standard_id: 'identity--4f347cc9-4658-59ee-9707-134f434f9d1c',
                updated_at: '2025-07-16T13:39:38.437Z',
                x_opencti_aliases: [
                  'Computer Incident',
                  'Incident'
                ],
                x_opencti_reliability: 'B - Usually reliable',
                x_opencti_stix_ids: [
                  'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132'
                ]
              }
            ],
            value: [
              {
                _id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
                _index: 'opencti_stix_domain_objects-000001',
                base_type: 'ENTITY',
                confidence: 100,
                created: '2020-03-27T08:39:45.676Z',
                created_at: '2025-07-16T13:39:39.321Z',
                creator_id: [
                  '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
                ],
                entity_type: 'Individual',
                i_aliases_ids: [],
                id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
                identity_class: 'individual',
                internal_id: '9006ee76-e229-4ee9-a61a-9a4473606d9e',
                lang: 'en',
                modified: '2025-07-16T13:39:39.333Z',
                name: 'John Doe',
                'object-label': [
                  '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
                ],
                parent_types: [
                  'Basic-Object',
                  'Stix-Object',
                  'Stix-Core-Object',
                  'Stix-Domain-Object',
                  'Identity'
                ],
                'rel_object-label.internal_id.keyword': [
                  '7afbdd63-fb77-47c8-bd9f-5a852fe8fbe9'
                ],
                standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
                updated_at: '2025-07-16T13:39:39.333Z',
                x_opencti_stix_ids: [
                  'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f'
                ]
              }
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_MALWARE, data);
    expect(message).toEqual('replaces `admin` with `John Doe` in `Author`');
  });
});
// should not:
// admin@opencti.io adds backdoor, bootkit with ransomware in Malware types - covid-19 in Label | replaces true with false in Is family
