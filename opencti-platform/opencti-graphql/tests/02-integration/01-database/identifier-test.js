/* eslint-disable no-underscore-dangle */
import { elLoadById, } from '../../../src/database/engine';
import { ADMIN_USER } from '../../utils/testQuery';
import {
  generateStandardId,
  isStandardIdDowngraded,
  isStandardIdSameWay,
  isStandardIdUpgraded
} from '../../../src/schema/identifier';
import { ENTITY_USER_ACCOUNT } from '../../../src/schema/stixCyberObservable';

describe('Identifier generation test', () => {
  it('should way change detected correctly', async () => {
    // [D.ENTITY_TYPE_MALWARE]: [{ src: NAME_FIELD }]
    const malware = await elLoadById(ADMIN_USER, 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const isMalwareChangeWay = isStandardIdSameWay(malware, malware);
    expect(isMalwareChangeWay).toBeTruthy();
    // [D.ENTITY_TYPE_COURSE_OF_ACTION]: [[{ src: X_MITRE_ID_FIELD }], [{ src: NAME_FIELD }]]
    const course = await elLoadById(ADMIN_USER, 'course-of-action--2d3af28d-aa36-59ad-ac57-65aa27664752');
    let isCourseChangeWay = isStandardIdSameWay(course, course);
    expect(isCourseChangeWay).toBeTruthy();
    // add the mitreID, way will change
    const changeCourse = { ...course, x_mitre_id: 'ID01' };
    isCourseChangeWay = isStandardIdSameWay(course, changeCourse);
    expect(isCourseChangeWay).toBeFalsy();
    // [M.ENTITY_TYPE_MARKING_DEFINITION]: [{ src: 'definition' }, { src: 'definition_type' }]
    const marking = await elLoadById(ADMIN_USER, 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27');
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
