import {describe, expect, it} from 'vitest';
import {buildChanges} from "../../../src/database/middleware";
import {ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE} from "../../../src/schema/stixDomainObject";

describe('buildChanges standard behavior', async () => {

  it('should build changes for simple attribute update (value replaced by other value in "description"', async () => {
    const inputs = [
      {
        "key": "description",
        "previous": ['description'],
        "value": ['new description']
      }
    ]
   const changes = buildChanges(ENTITY_TYPE_MALWARE, inputs)
    expect(changes).toEqual([{
      field: 'Description',
      previous: ['description'],
      new: ['new description']
    }]);
  });
  it('should build changes for simple attribute update (nothing replaced by something in "description")', async () => {
    const inputs = [
      {
        "key": "description",
        "previous": [],
        "value": ['description']
      }
    ]
    const changes = buildChanges(ENTITY_TYPE_MALWARE, inputs)
    expect(changes).toEqual([{
      field: 'Description',
      previous: [],
      new: ['description']
    }]);
  });
  it('should build changes for simple attribute update (something replaced by nothing in "description")', async () => {
    const inputs = [
      {
        "key": "description",
        "previous": ['description'],
        "value": []
      }
    ]
    const changes = buildChanges(ENTITY_TYPE_MALWARE, inputs)
    expect(changes).toEqual([{
      field: 'Description',
      previous: ['description'],
      new: []
    }]);
  });
  it('should build changes for multiple attribute update ("Malware types" added)', async () => {
    const inputs = [{key:'malware_types',previous:['backdoor'],value:['backdoor', 'bootkit']}]
    const changes = buildChanges(ENTITY_TYPE_MALWARE, inputs)
    expect(changes).toEqual([{field:"Malware types", previous: ['backdoor'], added:['bootkit'],removed:[]}]);
  });
  it('should build changes for mutliple attribute update ("Malware types" removed)', async () => {
    const inputs = [
      {
        key: 'malware_types',
        previous: ['backdoor', 'bootkit'],
        value: ['backdoor']
      }
    ]
    const changes = buildChanges(ENTITY_TYPE_MALWARE, inputs)
    expect(changes).toEqual([{field: 'Malware types', previous: ['backdoor', 'bootkit'], added:[], removed:['bootkit']}]);
  });
  it('should build changes for mutliple attribute update ("participant" added )', async () => {
    const inputs = [{
      key:"objectParticipant",
      operation:"add",
      value:[{
        entity_type:"User",
        id:"9b854803-7158-4e4e-a492-f8845ac33aad",
        name:"User 1",
        user_email:"user1@user1.com"}]}];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{field:'Participants', previous: [], added:['User 1'],removed:[]}]);
  })
  it('should build changes for mutliple attribute update (second "participant" added )', async () => {
    const inputs = [{
      key:"objectParticipant",
      operation:"add",
      value:[{
        entity_type:"User",
        id:"9b854803-7158-4e4e-a492-f8845ac33aad",
        name:"User 1",
      },
        {
        entity_type:"User",
        id:"7c854803-7158-4e4e-a492-f8845ac33agp",
        name:"User 2",
        }],
    previous:[{
      entity_type:"User",
      id:"9b854803-7158-4e4e-a492-f8845ac33aad",
      name:"User 1",
      }]}];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{field: 'Participants', previous: ["User 1"], added:['User 2'],removed:[]}]);
  })
  it('should build changes for mutliple attribute update ("marking" added )', async () => {
    const inputs = [
      {
        "key": "objectMarking",
        "operation": "add",
        "value": [
          {
            "_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:54.071Z",
            "created_at": "2025-11-20T09:49:54.071Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "TLP:GREEN",
            "definition_type": "TLP",
            "entity_type": "Marking-Definition",
            "id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "internal_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "modified": "2025-11-20T09:49:54.071Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:54.451Z",
            "sort": [
              "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "standard_id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "updated_at": "2025-11-20T09:49:54.071Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          }
        ]
      }
    ];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{field:"Markings",previous:[],added:["TLP:GREEN"],removed:[]}]);
  })
  it('should build changes for mutliple attribute update (second "marking" added )', async () => {
    const inputs = [
      {
        "key": "objectMarking",
        "operation": "add",
        "previous": [
          {
            "_id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:56.743Z",
            "created_at": "2025-11-20T09:49:56.743Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "PAP:GREEN",
            "definition_type": "PAP",
            "entity_type": "Marking-Definition",
            "i_relation": {
              "_id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "_index": "opencti3_stix_meta_relationships-000001",
              "base_type": "RELATION",
              "entity_type": "object-marking",
              "fromId": "f1ee945e-7d58-47ab-8bf8-444eb5321d0f",
              "fromName": "to be shared",
              "fromRole": "object-marking_from",
              "fromType": "Report",
              "id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "internal_id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "relationship_type": "object-marking",
              "sort": [
                "relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6"
              ],
              "source_ref": "report--temporary",
              "standard_id": "relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6",
              "target_ref": "marking-definition--temporary",
              "toId": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
              "toName": "PAP:GREEN",
              "toRole": "object-marking_to",
              "toType": "Marking-Definition"
            },
            "id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "internal_id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "modified": "2025-11-20T09:49:56.743Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:57.072Z",
            "standard_id": "marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1",
            "updated_at": "2025-11-20T09:49:56.743Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          }
        ],
        "value": [
          {
            "_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:54.071Z",
            "created_at": "2025-11-20T09:49:54.071Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "TLP:GREEN",
            "definition_type": "TLP",
            "entity_type": "Marking-Definition",
            "id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "internal_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "modified": "2025-11-20T09:49:54.071Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:54.451Z",
            "sort": [
              "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "standard_id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "updated_at": "2025-11-20T09:49:54.071Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          }
        ]
      }
    ];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{field:"Markings",previous:["PAP:GREEN"],added:["TLP:GREEN"],removed:[]}]);
  })
  it('should build changes for mutliple attribute update (second "marking" removed )', async () => {
    const inputs = [
      {
        "key": "objectMarking",
        "operation": "remove",
        "previous": [
          {
            "_id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:56.743Z",
            "created_at": "2025-11-20T09:49:56.743Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "PAP:GREEN",
            "definition_type": "PAP",
            "entity_type": "Marking-Definition",
            "i_relation": {
              "_id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "_index": "opencti3_stix_meta_relationships-000001",
              "base_type": "RELATION",
              "entity_type": "object-marking",
              "fromId": "f1ee945e-7d58-47ab-8bf8-444eb5321d0f",
              "fromName": "to be shared",
              "fromRole": "object-marking_from",
              "fromType": "Report",
              "id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "internal_id": "8c8a7868-6060-4b40-8798-1b4f1edead60",
              "relationship_type": "object-marking",
              "sort": [
                "relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6"
              ],
              "source_ref": "report--temporary",
              "standard_id": "relationship-meta--2d6b06d7-d9fc-42d6-9837-7fb1ede6add6",
              "target_ref": "marking-definition--temporary",
              "toId": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
              "toName": "PAP:GREEN",
              "toRole": "object-marking_to",
              "toType": "Marking-Definition"
            },
            "id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "internal_id": "23d0a2ce-8aee-4b06-885e-4c0b355cbffa",
            "modified": "2025-11-20T09:49:56.743Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:57.072Z",
            "standard_id": "marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1",
            "updated_at": "2025-11-20T09:49:56.743Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          },
          {
            "_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:54.071Z",
            "created_at": "2025-11-20T09:49:54.071Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "TLP:GREEN",
            "definition_type": "TLP",
            "entity_type": "Marking-Definition",
            "i_relation": {
              "_id": "3f3e2af0-c6aa-4425-a10c-ad76dcf6165b",
              "_index": "opencti3_stix_meta_relationships-000001",
              "base_type": "RELATION",
              "entity_type": "object-marking",
              "id": "3f3e2af0-c6aa-4425-a10c-ad76dcf6165b",
              "internal_id": "3f3e2af0-c6aa-4425-a10c-ad76dcf6165b",
              "sort": [
                "relationship-meta--394106e3-83bf-4f93-9cca-3442b69fd30a"
              ],
              "standard_id": "relationship-meta--394106e3-83bf-4f93-9cca-3442b69fd30a"
            },
            "id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "internal_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "modified": "2025-11-20T09:49:54.071Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:54.451Z",
            "standard_id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "updated_at": "2025-11-20T09:49:54.071Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          }
        ],
        "value": [
          {
            "_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "_index": "opencti3_stix_meta_objects-000001",
            "base_type": "ENTITY",
            "confidence": 100,
            "created": "2025-11-20T09:49:54.071Z",
            "created_at": "2025-11-20T09:49:54.071Z",
            "creator_id": [
              "6a4b11e1-90ca-4e42-ba42-db7bc7f7d505"
            ],
            "definition": "TLP:GREEN",
            "definition_type": "TLP",
            "entity_type": "Marking-Definition",
            "id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "internal_id": "6da54f1c-8c1b-4c61-953a-2ded39adcaba",
            "modified": "2025-11-20T09:49:54.071Z",
            "parent_types": [
              "Basic-Object",
              "Stix-Object",
              "Stix-Meta-Object"
            ],
            "refreshed_at": "2025-11-20T09:49:54.451Z",
            "standard_id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "updated_at": "2025-11-20T09:49:54.071Z",
            "x_opencti_color": "#2e7d32",
            "x_opencti_order": 2,
            "x_opencti_stix_ids": []
          }
        ]
      }
    ];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{field:"Markings",previous:["PAP:GREEN", "TLP:GREEN"],added:[],removed:["PAP:GREEN"]}]);
  })
});
