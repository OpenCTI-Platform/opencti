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
    expect(changes).toEqual([{"field":"Participants","previous":[],"new":['User 1']}]);
  })
  it('should build changes for mutliple attribute update (second "participant" added )', async () => {
    const inputs = [{
      key:"objectParticipant",
      operation:"add",
      value:[{
        entity_type:"User",
        id:"7c854803-7158-4e4e-a492-f8845ac33agp",
        name:"User 2",
        user_email:"user1@user1.com"}],
    previous:[{
      entity_type:"User",
      id:"9b854803-7158-4e4e-a492-f8845ac33aad",
      name:"User 1",
      user_email:"user1@user1.com"}]}];

    const changes = buildChanges(ENTITY_TYPE_CONTAINER_REPORT, inputs)
    expect(changes).toEqual([{"field":"Participants","previous":['User 1'],"new":['User 1', 'User 2']}]);
  })
});
