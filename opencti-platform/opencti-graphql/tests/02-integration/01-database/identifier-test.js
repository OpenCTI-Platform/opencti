/* eslint-disable no-underscore-dangle */
import { expect, it, describe } from 'vitest';
import { elLoadById, } from '../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import {
  allFieldsContributingToStandardId,
  generateHashedObservableStandardIds,
  generateStandardId,
  isStandardIdDowngraded,
  isStandardIdSameWay,
  isStandardIdUpgraded
} from '../../../src/schema/identifier';
import { ENTITY_DIRECTORY, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_USER_ACCOUNT } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../../../src/schema/stixDomainObject';
import { BASE_TYPE_RELATION } from '../../../src/schema/general';

describe('Identifier generation test', () => {
  it('should way change detected correctly', async () => {
    // [D.ENTITY_TYPE_MALWARE]: [{ src: NAME_FIELD }]
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const isMalwareChangeWay = isStandardIdSameWay(malware, malware);
    expect(isMalwareChangeWay).toBeTruthy();
    // [D.ENTITY_TYPE_COURSE_OF_ACTION]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]]
    const course = await elLoadById(testContext, ADMIN_USER, 'course-of-action--2d3af28d-aa36-59ad-ac57-65aa27664752');
    let isCourseChangeWay = isStandardIdSameWay(course, course);
    expect(isCourseChangeWay).toBeTruthy();
    // add the mitreID, way will change
    const changeCourse = { ...course, x_mitre_id: 'ID01' };
    isCourseChangeWay = isStandardIdSameWay(course, changeCourse);
    expect(isCourseChangeWay).toBeFalsy();
    // [M.ENTITY_TYPE_MARKING_DEFINITION]: [{ src: 'definition' }, { src: 'definition_type' }]
    const marking = await elLoadById(testContext, ADMIN_USER, 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27');
    let isMarkingChangeWay = isStandardIdSameWay(marking, marking);
    expect(isMarkingChangeWay).toBeTruthy();
    const changeMarking = { ...marking };
    changeMarking.definition_type = 'NEW DEF';
    isMarkingChangeWay = isStandardIdSameWay(marking, changeMarking);
    expect(isMarkingChangeWay).toBeTruthy();
    const previousStandard = generateStandardId(marking.entity_type, marking);
    const newStandard = generateStandardId(marking.entity_type, changeMarking);
    expect(previousStandard !== newStandard).toBeTruthy();
  });

  it('should SDO upgrade detection accurate', async () => {
    const account = { entity_type: ENTITY_USER_ACCOUNT, account_type: 'sso' };
    // Test adding a key element
    let changeAccount = { entity_type: ENTITY_USER_ACCOUNT, account_type: 'sso', user_id: 'id' };
    let isUpgraded = isStandardIdUpgraded(account, changeAccount);
    expect(isUpgraded).toBeTruthy();
    // Test removing a key element
    changeAccount = { entity_type: ENTITY_USER_ACCOUNT };
    isUpgraded = isStandardIdUpgraded(account, changeAccount);
    expect(isUpgraded).toBeFalsy();
    // Test changing an element
    changeAccount = { entity_type: ENTITY_USER_ACCOUNT, account_type: 'sso2' };
    isUpgraded = isStandardIdUpgraded(account, changeAccount);
    expect(isUpgraded).toBeFalsy();
    // Test adding + changing an element
    changeAccount = { entity_type: ENTITY_USER_ACCOUNT, account_type: 'sso2', user_id: 'id' };
    isUpgraded = isStandardIdUpgraded(account, changeAccount);
    expect(isUpgraded).toBeFalsy();
  });

  it('should no change detected', async () => {
    const file = {
      name: 'test',
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e7',
        'SHA-256': '19640e31073a3b929e0ea434652f3d6d560a06bf653f60530141bf4660227e02'
      },
    };
    // File move to MD5 way
    const changeFile = {
      name: 'test',
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e7',
        'SHA-256': '19640e31073a3b929e0ea434652f3d6d560a06bf653f60530141bf4660227e02'
      },
    };
    const isUpgraded = isStandardIdUpgraded(file, changeFile);
    const isDowngraded = isStandardIdDowngraded(file, changeFile);
    expect(isUpgraded).toBeFalsy();
    expect(isDowngraded).toBeFalsy();
  });

  it('should File way change detection accurate', async () => {
    const file = { name: 'test', entity_type: 'StixFile' };
    // File move to MD5 way
    const changeFile = {
      name: 'test',
      entity_type: 'StixFile',
      hashes: { MD5: '757a71f0fbd6b3d993be2a213338d1f2' },
    };
    const isUpgraded = isStandardIdUpgraded(file, changeFile);
    expect(isUpgraded).toBeFalsy();
  });

  it('should SCO upgrade detection accurate', async () => {
    const file = {
      name: null,
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e7'
      },
    };
    // Test adding a key element
    let changeFile = {
      name: null,
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e7',
        'SHA-256': '19640e31073a3b929e0ea434652f3d6d560a06bf653f60530141bf4660227e02'
      },
    };
    let isUpgraded = isStandardIdUpgraded(file, changeFile);
    expect(isUpgraded).toBeTruthy();
    // Test removing a key element
    changeFile = {
      name: null,
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
      },
    };
    isUpgraded = isStandardIdUpgraded(file, changeFile);
    expect(isUpgraded).toBeFalsy();
    // Test changing an element
    changeFile = {
      name: null,
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e8'
      },
    };
    isUpgraded = isStandardIdUpgraded(file, changeFile);
    expect(isUpgraded).toBeFalsy();
    // Test adding + changing an element
    changeFile = {
      name: null,
      entity_type: 'StixFile',
      hashes: {
        MD5: '757a71f0fbd6b3d993be2a213338d1f2',
        'SHA-1': 'ebe874c468d4b1b78fa4b3a7b3653b45db0da0e8',
        'SHA-256': '19640e31073a3b929e0ea434652f3d6d560a06bf653f60530141bf4660227e02'
      },
    };
    isUpgraded = isStandardIdUpgraded(file, changeFile);
    expect(isUpgraded).toBeFalsy();
  });
});

describe('Function allFieldsContributingToStandardId', () => {
  it('should return an empty array if properties is not an object', () => {
    const fields = allFieldsContributingToStandardId({ entity_type: ENTITY_TYPE_SETTINGS });
    expect(fields).toEqual([]);
  });

  it('should return false if its a relation', () => {
    const fields = allFieldsContributingToStandardId({ base_type: BASE_TYPE_RELATION });
    expect(fields).toEqual(false);
  });

  it('should return the list of fields contributing', () => {
    let fields = allFieldsContributingToStandardId({ entity_type: ENTITY_DIRECTORY });
    expect(fields).toEqual(['path']);
    fields = allFieldsContributingToStandardId({ entity_type: ENTITY_HASHED_OBSERVABLE_STIX_FILE });
    expect(fields).toEqual(['hashes', 'name']);
    fields = allFieldsContributingToStandardId({ entity_type: ENTITY_TYPE_CONTAINER_NOTE });
    expect(fields).toEqual(['content', 'created']);
  });
  describe('Function generateHashedObservableStandardIds', () => {
    it('should generate HashedObservable standardIds work', () => {
      const instanceUrl = {
        _index: 'opencti_stix_cyber_observables-000001',
        _id: '9c839484-4302-4c17-b972-dad97fdb3eef',
        id: '9c839484-4302-4c17-b972-dad97fdb3eef',
        sort: [1751527593131],
        x_opencti_score: 50,
        x_opencti_description: '',
        value: 'https://cybermap.kaspersky.com/',
        confidence: 100,
        entity_type: 'Url',
        internal_id: '9c839484-4302-4c17-b972-dad97fdb3eef',
        standard_id: 'url--5e9f7011-48db-5fcf-a301-c7ac27b2a082',
        creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
        x_opencti_stix_ids: [],
        created_at: '2025-07-03T07:26:33.131Z',
        updated_at: '2025-07-03T07:30:55.752Z',
        base_type: 'ENTITY',
        parent_types: [
          'Basic-Object',
          'Stix-Object',
          'Stix-Core-Object',
          'Stix-Cyber-Observable'
        ],
        i_attributes: [
          {
            updated_at: '2025-07-03T07:30:55.752Z',
            user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
            confidence: 100,
            name: 'x_opencti_description'
          }
        ]
      };

      const instanceType = instanceUrl.entity_type;
      const urlValue = instanceUrl.value;
      const standardIdsUrl = generateHashedObservableStandardIds(instanceUrl);
      expect(instanceType).toEqual('Url');
      expect(urlValue).toEqual('https://cybermap.kaspersky.com/');
      expect(standardIdsUrl).toEqual([]);
    });
  });
});
