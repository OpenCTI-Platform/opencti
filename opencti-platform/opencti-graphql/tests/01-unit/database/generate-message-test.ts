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
    expect(message).toEqual('replaces `user1 (admin)` with `user1 (admin), user2 (edit)` in `Authorized members`');
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
});// TODO tests for creators update, string + json, date, object and request access
