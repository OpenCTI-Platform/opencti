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
  it('should generate message for Authorized members update', () => {
    const data = {
      creators: [],
      members: [
        {
          internal_id: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddf',
          name: 'User1'
        },
        {
          internal_id: 'fgg2afb7-07d3-50ad-bdd0-d6977f045ddf',
          name: 'User2'
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
              id: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddf'
            }],
            value: [{
              access_right: 'admin',
              id: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddf'
            },
            {
              access_right: 'edit',
              id: 'fgg2afb7-07d3-50ad-bdd0-d6977f045ddf'
            }
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(message).toEqual('replaces `User1 (admin)` with `User1 (admin), User2 (edit)` in `Authorized members`');
  });
  it('should generate message for Workflow status update', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'x_opencti_workflow_id',
            previous: [
              'NEW'
            ],
            value: [
              'ANALYZED'
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(message).toEqual('replaces `NEW` with `ANALYZED` in `Workflow status`');
  });
  it('should generate message for Workflow status update with request access', () => {
    const data = { creators: [], members: [] };
    const patchElements = [
      [
        'replace',
        [
          {
            key: 'x_opencti_workflow_id',
            previous: [
              'NEW'
            ],
            value: [
              'ANALYZED'
            ]
          },
          {
            key: 'x_opencti_request_access',
            previous: [],
            value: [
              JSON.stringify({ status: 'APPROVED' })
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(message).toEqual('replaces `NEW` with `ANALYZED (request access APPROVED)` in `Workflow status`');
  });
  it('should generate message for Creators update', () => {
    const data = { creators: [{
      id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      name: 'admin'
    },
    {
      id: '51c085a6-612a-463b-9575-27513bf85d99',
      name: 'user2'
    }],
    members: []
    };
    const patchElements = [
      [
        'add',
        [
          {
            key: 'creator_id',
            operation: 'add',
            previous: [
              '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
            ],
            value: [
              '51c085a6-612a-463b-9575-27513bf85d99'
            ]
          }
        ]
      ]
    ];
    const message = generateUpdatePatchMessage(patchElements, ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(message).toEqual('adds `user2` in `Creators`');
  });
});// TODO tests for string + json, date, object
