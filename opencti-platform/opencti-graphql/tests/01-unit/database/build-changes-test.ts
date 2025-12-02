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
    expect(changes).toEqual([{field:"Malware types",added:['bootkit'],removed:[]}]);
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
    expect(changes).toEqual([{field:"Malware types",added:[],removed:['bootkit']}]);
  });
  it('should build changes for mutliple attribute update ("authorized members" activation)', async () => {
    const inputs = [{
      key: 'restricted_members',
      previous: [],
      value: [{
          access_right: 'admin',
          id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
        }]
    }];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{
      field: 'Authorized members',
      added: [{
        id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        access_right: 'admin'
      }],
      removed: []
    }]);
  })
  it('should build changes for mutliple attribute update ("authorized members" added)', async () => {
    const inputs = [{
      key:"restricted_members",
      previous:[{
          access_right:"admin",
          id:"88ec0c6a-13ce-5e39-b486-354fe4a7084f"
        }],
      value:[{
          access_right:"admin",
          id:"88ec0c6a-13ce-5e39-b486-354fe4a7084f"
        },
        {
          access_right:"edit",
          id:"a29bba2c-2a69-47f9-9c50-013bf627ea5b"
        }]}];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual(
      [{
        field:"Authorized members",
        added:[{
          access_right:"admin",
          id:"88ec0c6a-13ce-5e39-b486-354fe4a7084f"
        },
          {
            access_right:"edit",
            id:"a29bba2c-2a69-47f9-9c50-013bf627ea5b"
          }],
        removed:[{
          access_right:"admin",
          id:"88ec0c6a-13ce-5e39-b486-354fe4a7084f"
        }]
      }]
    );
  })
  it('should build changes for mutliple attribute update ("participant" added)', async () => {
    const inputs = [{
      "key":"objectParticipant",
      "operation":"add",
      "value":[{
        "entity_type":"User",
        "id":"9b854803-7158-4e4e-a492-f8845ac33aad",
        "name":"User 1",
        "user_email":"user1@user1.com"}]}];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{"field":"Participants","previous":[],"new":['User 1']}]);
  })
});
