import {describe, expect, it} from 'vitest';
import {buildChanges} from '../../../src/database/middleware';
import {ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE} from '../../../src/schema/stixDomainObject';
import {ADMIN_USER, getUserIdByEmail, testContext, USER_EDITOR, USER_SECURITY} from '../../utils/testQuery';
import {findByType} from '../../../src/domain/status';
import {EditOperation} from '../../../src/generated/graphql';

describe('buildChanges standard behavior', async () => {

  it('should build changes for value replaced by other value in "description"', async () => {
    const inputs = [
      {
        'key': 'description',
        'previous': ['description'],
        'value': ['new description']
      }
    ];
   const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{
      field: 'Description',
      previous: ['description'],
      new: ['new description']
    }]);
  });
  it('should build changes for nothing replaced by something in "description"', async () => {
    const inputs = [
      {
        'key': 'description',
        'previous': [],
        'value': ['description']
      }
    ];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{
      field: 'Description',
      previous: [],
      new: ['description']
    }]);
  });
  it('should build changes for something replaced by nothing in "description"', async () => {
    const inputs = [
      {
        'key': 'description',
        'previous': ['description'],
        'value': []
      }
    ];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{
      field: 'Description',
      previous: ['description'],
      new: []
    }]);
  });
  it('should build changes for "Malware types" added', async () => {
    const inputs = [{key:'malware_types',previous:['backdoor'],value:['backdoor', 'bootkit']}];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{field:'Malware types', previous: ['backdoor'], new: ['backdoor', 'bootkit'], added:['bootkit'],removed:[]}]);
  });
  it('should build changes for "Malware types" removed', async () => {
    const inputs = [
      {
        key: 'malware_types',
        previous: ['backdoor', 'bootkit'],
        value: ['backdoor']
      }
    ];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{field: 'Malware types', previous: ['backdoor', 'bootkit'], new: ['backdoor'], added:[], removed:['bootkit']}]);
  });
  it('should build changes for "participant" added ', async () => {
    const inputs = [{
      key:'objectParticipant',
      operation:EditOperation.Add,
      value:[{
        entity_type:'User',
        id:'9b854803-7158-4e4e-a492-f8845ac33aad',
        name:'User 1',
        user_email:'user1@user1.com'}]}];

    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Participants', previous: [], new: ['User 1'], added:['User 1'],removed:[]}]);
  });
  it('should build changes for second "participant" added ', async () => {
    const inputs = [{
      key:'objectParticipant',
      operation:EditOperation.Add,
      value:[
        {
        entity_type:'User',
        id:'7c854803-7158-4e4e-a492-f8845ac33agp',
        name:'User 2',
        }],
    previous:[{
      entity_type:'User',
      id:'9b854803-7158-4e4e-a492-f8845ac33aad',
      name:'User 1',
      }]}];

    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field: 'Participants', previous: ['User 1'], new: ['User 1', 'User 2'], added:['User 2'],removed:[]}]);
  });
  it('should build changes for "marking" added', async () => {
    const inputs = [
      {
        'key': 'objectMarking',
        'operation': EditOperation.Add,
        'value': [
          {
            '_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:54.071Z',
            'created_at': '2025-11-20T09:49:54.071Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'TLP:GREEN',
            'definition_type': 'TLP',
            'entity_type': 'Marking-Definition',
            'id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'internal_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'modified': '2025-11-20T09:49:54.071Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:54.451Z',
            'sort': [
              'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
            ],
            'standard_id': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            'updated_at': '2025-11-20T09:49:54.071Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          }
        ]
      }
    ];

    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Markings',previous:[], new: ['TLP:GREEN'], added:['TLP:GREEN'],removed:[]}]);
  });
  it('should build changes for second "marking" added', async () => {
    const inputs = [
      {
        'key': 'objectMarking',
        'operation': EditOperation.Add,
        'previous': [
          {
            '_id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:56.743Z',
            'created_at': '2025-11-20T09:49:56.743Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'PAP:GREEN',
            'definition_type': 'PAP',
            'entity_type': 'Marking-Definition',
            'i_relation': {
              '_id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              '_index': 'opencti3_stix_meta_relationships-000001',
              'base_type': 'RELATION',
              'entity_type': 'object-marking',
              'fromId': 'f1ee945e-7d58-47ab-8bf8-444eb5321d0f',
              'fromName': 'to be shared',
              'fromRole': 'object-marking_from',
              'fromType': 'Report',
              'id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              'internal_id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              'relationship_type': 'object-marking',
              'sort': [
                'relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6'
              ],
              'source_ref': 'report--temporary',
              'standard_id': 'relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6',
              'target_ref': 'marking-definition--temporary',
              'toId': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
              'toName': 'PAP:GREEN',
              'toRole': 'object-marking_to',
              'toType': 'Marking-Definition'
            },
            'id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            'internal_id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            'modified': '2025-11-20T09:49:56.743Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:57.072Z',
            'standard_id': 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
            'updated_at': '2025-11-20T09:49:56.743Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          }
        ],
        'value': [
          {
            '_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:54.071Z',
            'created_at': '2025-11-20T09:49:54.071Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'TLP:GREEN',
            'definition_type': 'TLP',
            'entity_type': 'Marking-Definition',
            'id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'internal_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'modified': '2025-11-20T09:49:54.071Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:54.451Z',
            'sort': [
              'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
            ],
            'standard_id': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            'updated_at': '2025-11-20T09:49:54.071Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          }
        ]
      }
    ];

    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Markings',previous:['PAP:GREEN'], new: ['PAP:GREEN', 'TLP:GREEN'], added:['TLP:GREEN'],removed:[]}]);
  });
  it('should build changes for second "marking" removed', async () => {
    const inputs = [
      {
        'key': 'objectMarking',
        'operation': EditOperation.Remove,
        'previous': [
          {
            '_id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:56.743Z',
            'created_at': '2025-11-20T09:49:56.743Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'PAP:GREEN',
            'definition_type': 'PAP',
            'entity_type': 'Marking-Definition',
            'i_relation': {
              '_id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              '_index': 'opencti3_stix_meta_relationships-000001',
              'base_type': 'RELATION',
              'entity_type': 'object-marking',
              'fromId': 'f1ee945e-7d58-47ab-8bf8-444eb5321d0f',
              'fromName': 'to be shared',
              'fromRole': 'object-marking_from',
              'fromType': 'Report',
              'id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              'internal_id': '8c8a7868-6060-4b40-8798-1b4f1edead60',
              'relationship_type': 'object-marking',
              'sort': [
                'relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6'
              ],
              'source_ref': 'report--temporary',
              'standard_id': 'relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6',
              'target_ref': 'marking-definition--temporary',
              'toId': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
              'toName': 'PAP:GREEN',
              'toRole': 'object-marking_to',
              'toType': 'Marking-Definition'
            },
            'id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            'internal_id': '23d0a2ce-8aee-4b06-885e-4c0b355cbffa',
            'modified': '2025-11-20T09:49:56.743Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:57.072Z',
            'standard_id': 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
            'updated_at': '2025-11-20T09:49:56.743Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          },
          {
            '_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:54.071Z',
            'created_at': '2025-11-20T09:49:54.071Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'TLP:GREEN',
            'definition_type': 'TLP',
            'entity_type': 'Marking-Definition',
            'i_relation': {
              '_id': '3f3e2af0-c6aa-4425-a10c-ad76dcf6165b',
              '_index': 'opencti3_stix_meta_relationships-000001',
              'base_type': 'RELATION',
              'entity_type': 'object-marking',
              'id': '3f3e2af0-c6aa-4425-a10c-ad76dcf6165b',
              'internal_id': '3f3e2af0-c6aa-4425-a10c-ad76dcf6165b',
              'sort': [
                'relationship-meta--394106e3-83bf-4f93-9cca-3442b69fd30a'
              ],
              'standard_id': 'relationship-meta--394106e3-83bf-4f93-9cca-3442b69fd30a'
            },
            'id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'internal_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'modified': '2025-11-20T09:49:54.071Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:54.451Z',
            'standard_id': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            'updated_at': '2025-11-20T09:49:54.071Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          }
        ],
        'value': [
          {
            '_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            '_index': 'opencti3_stix_meta_objects-000001',
            'base_type': 'ENTITY',
            'confidence': 100,
            'created': '2025-11-20T09:49:54.071Z',
            'created_at': '2025-11-20T09:49:54.071Z',
            'creator_id': [
              '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
            ],
            'definition': 'TLP:GREEN',
            'definition_type': 'TLP',
            'entity_type': 'Marking-Definition',
            'id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'internal_id': '6da54f1c-8c1b-4c61-953a-2ded39adcaba',
            'modified': '2025-11-20T09:49:54.071Z',
            'parent_types': [
              'Basic-Object',
              'Stix-Object',
              'Stix-Meta-Object'
            ],
            'refreshed_at': '2025-11-20T09:49:54.451Z',
            'standard_id': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            'updated_at': '2025-11-20T09:49:54.071Z',
            'x_opencti_color': '#2e7d32',
            'x_opencti_order': 2,
            'x_opencti_stix_ids': []
          }
        ]
      }
    ];

    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Markings',previous:['PAP:GREEN', 'TLP:GREEN'], new: ['PAP:GREEN'], added:[],removed:['TLP:GREEN']}]);
  });
  it('should build changes for integer (like confidence level)', async () => {
    const inputs = [{'key':'confidence','previous':[58],'value':[52]}];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Confidence',previous:[58], new: [52]}]);
  });
  it('should build changes for labels removed', async () => {
    const inputs =
  [
    {
      'key': 'objectLabel',
      'operation': EditOperation.Remove,
      'previous': [
        {
          '_id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          '_index': 'opencti_stix_meta_objects-000001',
          'base_type': 'ENTITY',
          'color': '#5ce3b1',
          'confidence': 100,
          'created': '2025-10-28T13:58:44.914Z',
          'created_at': '2025-10-28T13:58:44.914Z',
          'creator_id': [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ],
          'entity_type': 'Label',
          'i_relation': {
            '_id': 'd86192fa-3d75-4930-b984-af07ff2c5c68',
            '_index': 'opencti_stix_meta_relationships-000001',
            'base_type': 'RELATION',
            'entity_type': 'object-label',
            'fromId': '66cba5b6-fa96-4ec5-bbd3-6f277d56e926',
            'fromName': 'coucou',
            'fromRole': 'object-label_from',
            'fromType': 'Report',
            'id': 'd86192fa-3d75-4930-b984-af07ff2c5c68',
            'internal_id': 'd86192fa-3d75-4930-b984-af07ff2c5c68',
            'relationship_type': 'object-label',
            'sort': [
              'relationship-meta--01c2fc35-74b8-4138-bfa2-a8a52e5bc5a8'
            ],
            'source_ref': 'report--temporary',
            'standard_id': 'relationship-meta--01c2fc35-74b8-4138-bfa2-a8a52e5bc5a8',
            'target_ref': 'label--temporary',
            'toId': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
            'toName': 'anti-sandbox',
            'toRole': 'object-label_to',
            'toType': 'Label'
          },
          'id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          'internal_id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          'modified': '2025-10-28T13:58:44.914Z',
          'parent_types': [
            'Basic-Object',
            'Stix-Object',
            'Stix-Meta-Object'
          ],
          'refreshed_at': '2025-10-28T16:14:59.505Z',
          'standard_id': 'label--84f47fea-17d1-58bd-88ee-053d92e591c0',
          'updated_at': '2025-10-28T13:58:44.914Z',
          'value': 'anti-sandbox',
          'x_opencti_stix_ids': []
        },
        {
          '_id': '8cee9d94-105e-42ae-ad56-cae421a927a2',
          '_index': 'opencti_stix_meta_objects-000001',
          'base_type': 'ENTITY',
          'color': '#bd10e0',
          'confidence': 100,
          'created': '2025-10-21T09:22:42.066Z',
          'created_at': '2025-10-21T09:22:42.066Z',
          'creator_id': [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ],
          'entity_type': 'Label',
          'i_relation': {
            '_id': '11b424c7-d914-4e3a-9c1c-7377a1cef35f',
            '_index': 'opencti_stix_meta_relationships-000001',
            'base_type': 'RELATION',
            'entity_type': 'object-label',
            'fromId': '66cba5b6-fa96-4ec5-bbd3-6f277d56e926',
            'fromName': 'coucou',
            'fromRole': 'object-label_from',
            'fromType': 'Report',
            'id': '11b424c7-d914-4e3a-9c1c-7377a1cef35f',
            'internal_id': '11b424c7-d914-4e3a-9c1c-7377a1cef35f',
            'sort': [
              'relationship-meta--13d16999-d63a-4862-bbbc-58590107d6f0'
            ],
            'source_ref': 'report--temporary',
            'standard_id': 'relationship-meta--13d16999-d63a-4862-bbbc-58590107d6f0'
          },
          'id': '8cee9d94-105e-42ae-ad56-cae421a927a2',
          'internal_id': '8cee9d94-105e-42ae-ad56-cae421a927a2',
          'modified': '2025-10-21T09:22:42.066Z',
          'parent_types': [
            'Basic-Object',
            'Stix-Object',
            'Stix-Meta-Object'
          ],
          'refreshed_at': '2025-10-21T09:22:42.066Z',
          'standard_id': 'label--f5658bbf-8549-5a15-9194-0c3d502a8c2a',
          'updated_at': '2025-10-21T09:22:42.066Z',
          'value': 'angie',
          'x_opencti_stix_ids': []
        }
      ],
      'value': [
        {
          '_id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          '_index': 'opencti_stix_meta_objects-000001',
          'base_type': 'ENTITY',
          'color': '#5ce3b1',
          'confidence': 100,
          'created': '2025-10-28T13:58:44.914Z',
          'created_at': '2025-10-28T13:58:44.914Z',
          'creator_id': [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ],
          'entity_type': 'Label',
          'id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          'internal_id': 'd9c27d81-c003-4a0d-bfdc-397b8d12f59c',
          'modified': '2025-10-28T13:58:44.914Z',
          'parent_types': [
            'Basic-Object',
            'Stix-Object',
            'Stix-Meta-Object'
          ],
          'refreshed_at': '2025-10-28T16:14:59.505Z',
          'standard_id': 'label--84f47fea-17d1-58bd-88ee-053d92e591c0',
          'updated_at': '2025-10-28T13:58:44.914Z',
          'value': 'anti-sandbox',
          'x_opencti_stix_ids': []
        }
      ]
    }
  ];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Label',previous:['anti-sandbox', 'angie'], new: ['angie'], removed:['anti-sandbox'], added:[]}]);
  });
  it('should build changes for status replaced', async () => {
    // we use data-initialization statuses
    const statuses = await findByType(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT);
    const inputs = [{
      key:'x_opencti_workflow_id',
      previous:[statuses[0].id],
      value:[statuses[1].id]
    }];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Workflow status',previous:[statuses[0].name],new:[statuses[1].name]}]);
  });
  it('should build changes for creator add', async () => {
    const securityId = await getUserIdByEmail(USER_SECURITY.email);
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    const inputs = [{
      key:'creator_id',
      previous:[securityId],
      value:[securityId, editorId]
    }];
    const changes = await buildChanges(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, inputs);
    expect(changes).toEqual([{field:'Creators',previous:['security@opencti.io'],new:['security@opencti.io','editor@opencti.io'],added:['editor@opencti.io'],removed:[]}]);
  });
});

