import { describe, expect, it } from 'vitest';
import { generateAliasesId, generateStandardId, normalizeName } from '../../../src/schema/identifier';
import { cleanStixIds } from '../../../src/database/stix';
import { generateInternalType } from '../../../src/schema/schemaUtils';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

import '../../../src/modules/index';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../src/modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../src/modules/administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../../../src/modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CHANNEL } from '../../../src/modules/channel/channel-types';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_LANGUAGE } from '../../../src/modules/language/language-types';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../../../src/modules/malwareAnalysis/malwareAnalysis-types';
import { ENTITY_TYPE_NARRATIVE } from '../../../src/modules/narrative/narrative-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../../../src/modules/task/task-types';
import { ENTITY_TYPE_VOCABULARY } from '../../../src/modules/vocabulary/vocabulary-types';
import { RELATION_BASED_ON } from '../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../../src/modules/case/feedback/feedback-types'; // Need to import registration files

describe('identifier', () => {
  it('should name correctly normalize', () => {
    let normalize = normalizeName('My data %test     ');
    expect(normalize).toEqual('my data %test');
    normalize = normalizeName('My ♫̟  data  test ');
    expect(normalize).toEqual('my ♫̟  data  test');
    normalize = normalizeName('SnowFlake');
    expect(normalize).toEqual('snowflake');
  });

  // !! WARNING !!, this need to be changed along with tests/01-unit/stix/test_bundle_ids_rewrite.py
  it('should ids generated correctly', () => {
    // attack_pattern
    expect(generateStandardId(ENTITY_TYPE_ATTACK_PATTERN, { name: 'attack' })).toEqual('attack-pattern--25f21617-8de8-5d5e-8cd4-b7e88547ba76');
    expect(generateStandardId(ENTITY_TYPE_ATTACK_PATTERN, { name: 'attack', x_mitre_id: 'MITREID' })).toEqual('attack-pattern--b74cfee2-7b14-585e-862f-fea45e802da9');
    expect(generateStandardId(ENTITY_TYPE_ATTACK_PATTERN, { name: 'Spear phishing messages with malicious links', x_mitre_id: 'T1368' })).toEqual('attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890');
    expect(generateStandardId(ENTITY_TYPE_ATTACK_PATTERN, { x_mitre_id: 'MITREID' })).toEqual('attack-pattern--b74cfee2-7b14-585e-862f-fea45e802da9');
    // campaign
    expect(generateStandardId(ENTITY_TYPE_CAMPAIGN, { name: 'attack' })).toEqual('campaign--25f21617-8de8-5d5e-8cd4-b7e88547ba76');
    // note
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_NOTE, { content: 'My note content!' })).toEqual('note--2b4ab5af-2307-58e1-8862-a6a269aae798');
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_NOTE, { content: 'My note content!', created: '2022-11-25T19:00:05.000Z' })).toEqual('note--10861e5c-049e-54f6-9736-81c106e39a0b');
    // observed-data
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { objects: [{ standard_id: 'id' }] })).toEqual('observed-data--4765c523-81bc-54c8-b1af-ee81d961dad1');
    // opinion
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_OPINION, { opinion: 'Good' })).toEqual('opinion--0aef8829-207e-508b-b1f1-9da07f3379cb');
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_OPINION, { opinion: 'Good', created: '2022-11-25T19:00:05.000Z' })).toEqual('opinion--941dbd61-c6b1-5290-b63f-19a38983d7f7');
    // report
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, { name: 'Report', published: '2022-11-25T19:00:05.000Z' })).toEqual('report--761c6602-975f-5e5e-b220-7a2d41f33ce4');
    // course-of-action
    expect(generateStandardId(ENTITY_TYPE_COURSE_OF_ACTION, { x_mitre_id: 'MITREID' })).toEqual('course-of-action--b74cfee2-7b14-585e-862f-fea45e802da9');
    expect(generateStandardId(ENTITY_TYPE_COURSE_OF_ACTION, { x_mitre_id: 'MITREID', name: 'Name' })).toEqual('course-of-action--b74cfee2-7b14-585e-862f-fea45e802da9');
    expect(generateStandardId(ENTITY_TYPE_COURSE_OF_ACTION, { name: 'Name' })).toEqual('course-of-action--e6e2ee8d-e54d-50cd-b77c-df8c8eea7726');
    // identity
    expect(generateStandardId(ENTITY_TYPE_IDENTITY_INDIVIDUAL, { name: 'julien', identity_class: 'Individual' })).toEqual('identity--d969b177-497f-598d-8428-b128c8f5f819');
    expect(generateStandardId(ENTITY_TYPE_IDENTITY_SECTOR, { name: 'julien', identity_class: 'Sector' })).toEqual('identity--14ffa2a4-e16a-522a-937a-784c0ac1fab0');
    expect(generateStandardId(ENTITY_TYPE_IDENTITY_SYSTEM, { name: 'julien', identity_class: 'System' })).toEqual('identity--8af97482-121d-53f7-a533-9c48f06b5a38');
    expect(generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name: 'organization', identity_class: 'individual' })).toEqual('identity--00f7eb8c-6af2-5ed5-9ede-ede4c623de3b');
    // infrastructure
    expect(generateStandardId(ENTITY_TYPE_INFRASTRUCTURE, { name: 'infra' })).toEqual('infrastructure--8a20116f-5a41-5508-ae4b-c293ac67c527');
    // intrusion-set
    expect(generateStandardId(ENTITY_TYPE_INTRUSION_SET, { name: 'intrusion' })).toEqual('intrusion-set--30757026-c4bd-574d-ae52-8d8503b4818e');
    // location
    expect(generateStandardId(ENTITY_TYPE_LOCATION_CITY, { name: 'Lyon', x_opencti_location_type: 'City' })).toEqual('location--da430873-42c8-57ca-b08b-a797558c6cbd');
    expect(generateStandardId(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, { name: 'Lyon', x_opencti_location_type: 'Administrative-Area' })).toEqual('location--2ad8a94d-39cc-508c-b8b6-367783f9ecfe');
    expect(generateStandardId(ENTITY_TYPE_LOCATION_POSITION, { latitude: 5.12, name: 'Position1' })).toEqual('location--56b3fc50-5091-5f2e-bd19-7b40ee3881e4');
    expect(generateStandardId(ENTITY_TYPE_LOCATION_POSITION, { longitude: 5.12, name: 'Position2' })).toEqual('location--dd2cf94c-1d58-58a1-b21f-0ede4059aaf0');
    expect(generateStandardId(ENTITY_TYPE_LOCATION_POSITION, { latitude: 5.12, longitude: 5.12 })).toEqual('location--57acef55-747a-55ef-9c49-06ca85f8d749');
    expect(generateStandardId(ENTITY_TYPE_LOCATION_POSITION, { name: 'Position3' })).toEqual('location--a4152781-8721-5d44-ae2d-e492665bc35b');
    // malware
    expect(generateStandardId(ENTITY_TYPE_MALWARE, { name: 'malware' })).toEqual('malware--92ddf766-b27c-5159-8f46-27002bba2f04');
    // threat-actor-group
    expect(generateStandardId(ENTITY_TYPE_THREAT_ACTOR_GROUP, { name: 'CARD04' })).toEqual('threat-actor--6d458783-df3b-5398-8e30-282655ad7b94');
    // tool
    expect(generateStandardId(ENTITY_TYPE_TOOL, { name: 'my-tool' })).toEqual('tool--41cd21d0-f50e-5e3d-83fc-447e0def97b7');
    // vulnerability
    expect(generateStandardId(ENTITY_TYPE_VULNERABILITY, { name: 'vulnerability' })).toEqual('vulnerability--2c690168-aec3-57f1-8295-adf53f4dc3da');
    // incident
    expect(generateStandardId(ENTITY_TYPE_INCIDENT, { name: 'incident', created: '2022-11-25T19:00:05.000Z' })).toEqual('incident--0e117c15-0a94-5ad3-b090-0395613f5b29');
    // case-incident
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, { name: 'case', created: '2022-11-25T19:00:05.000Z' })).toEqual('case-incident--4838a141-bd19-542c-85d9-cce0382645b5');
    // case-rfi
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_CASE_RFI, { name: 'case', created: '2022-11-25T19:00:05.000Z' })).toEqual('case-rfi--4838a141-bd19-542c-85d9-cce0382645b5');
    // case-rft
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_CASE_RFT, { name: 'case', created: '2022-11-25T19:00:05.000Z' })).toEqual('case-rft--4838a141-bd19-542c-85d9-cce0382645b5');
    // feedback
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_FEEDBACK, { name: 'case', created: '2022-11-25T19:00:05.000Z' })).toEqual('feedback--4838a141-bd19-542c-85d9-cce0382645b5');
    // channel
    expect(generateStandardId(ENTITY_TYPE_CHANNEL, { name: 'channel' })).toEqual('channel--4936cdd5-6b6a-5c92-a756-cae1f09dcd80');
    // data-component
    expect(generateStandardId(ENTITY_TYPE_DATA_COMPONENT, { name: 'data-component' })).toEqual('data-component--32fdc52a-b4c5-5268-af2f-cdf820271f0b');
    // data-source
    expect(generateStandardId(ENTITY_TYPE_DATA_SOURCE, { name: 'data-source' })).toEqual('data-source--f0925972-35e1-5172-9161-4d7180908339');
    // grouping
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_GROUPING, { name: 'grouping', context: 'context' })).toEqual('grouping--8462bd42-4cad-54ae-a261-efc1a762d83d');
    // indicator
    expect(generateStandardId(ENTITY_TYPE_INDICATOR, { pattern: '[domain-name:value = \'shortsvelventysjo.shop\']' })).toEqual('indicator--e3a64916-7775-5262-9246-9d3783cfdfa6');
    // language
    expect(generateStandardId(ENTITY_TYPE_LANGUAGE, { name: 'fr' })).toEqual('language--0ef28873-9d49-5cdb-a53a-eb7613391ee9');
    // malware-analysis
    expect(generateStandardId(ENTITY_TYPE_MALWARE_ANALYSIS, { product: 'linux', result_name: 'result' })).toEqual('malware-analysis--3d501241-a4a5-574d-a503-301a6426f8c1');
    expect(generateStandardId(ENTITY_TYPE_MALWARE_ANALYSIS, { product: 'linux', result_name: 'result', submitted: '2022-11-25T19:00:05.000Z' })).toEqual('malware-analysis--d7ffe68a-0d5f-5fea-a375-3338ba4ea13c');
    // narrative
    expect(generateStandardId(ENTITY_TYPE_NARRATIVE, { name: 'narrative' })).toEqual('narrative--804a7e40-d39c-59b6-9e3f-1ba1bc92b739');
    // task
    expect(generateStandardId(ENTITY_TYPE_CONTAINER_TASK, { name: 'case', created: '2022-11-25T19:00:05.000Z' })).toEqual('task--4838a141-bd19-542c-85d9-cce0382645b5');
    // threat-actor-individual
    expect(generateStandardId(ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, { name: 'CARD04' })).toEqual('threat-actor--af15b6ae-a3dd-54d3-8fa0-3adfe0391d01');
    // vocabulary
    expect(generateStandardId(ENTITY_TYPE_VOCABULARY, { name: 'facebook', category: 'account_type_ov' })).toEqual('vocabulary--85ae7185-ff6f-509b-a011-3069921614aa');
    // relationship
    const baseRelationship = { relationship_type: RELATION_BASED_ON, from: { standard_id: 'from_id' }, to: { standard_id: 'to_id' } };
    expect(generateStandardId(RELATION_BASED_ON, baseRelationship)).toEqual('relationship--0b11fa67-da01-5d34-9864-67d4d71c3740');
    expect(generateStandardId(RELATION_BASED_ON, { ...baseRelationship, start_time: '2022-11-25T19:00:05.000Z' })).toEqual('relationship--c5e1e2ce-14d6-535b-911d-267e92119e01');
    expect(generateStandardId(RELATION_BASED_ON, { ...baseRelationship, start_time: '2022-11-25T19:00:05.000Z', stop_time: '2022-11-26T19:00:05.000Z' })).toEqual('relationship--a7778a7d-a743-5193-9912-89f88f9ed0b4');
    // sighting
    const baseSighting = { relationship_type: STIX_SIGHTING_RELATIONSHIP, from: { standard_id: 'from_id' }, to: { standard_id: 'to_id' } };
    expect(generateStandardId(STIX_SIGHTING_RELATIONSHIP, baseSighting)).toEqual('sighting--161901df-21bb-527a-b96b-354119279fe2');
    expect(generateStandardId(STIX_SIGHTING_RELATIONSHIP, { ...baseSighting, first_seen: '2022-11-25T19:00:05.000Z' })).toEqual('sighting--3c59ceea-8e41-5adb-a257-d070d19e6d2b');
    expect(generateStandardId(STIX_SIGHTING_RELATIONSHIP, { ...baseSighting, first_seen: '2022-11-25T19:00:05.000Z', last_seen: '2022-11-26T19:00:05.000Z' })).toEqual('sighting--b4d307b6-d22c-5f22-b530-876c298493da');
  });

  it('should aliases generated with normalization', () => {
    const classicId = generateStandardId(ENTITY_TYPE_MALWARE, { name: 'SnowFlake' });
    const aliasId = generateAliasesId(['SnowFlake'], { name: 'APT28', entity_type: ENTITY_TYPE_MALWARE }).at(0);
    expect(classicId).toEqual('malware--1bc77052-c136-5258-b95d-fc8117fba3fd');
    expect(classicId).toEqual(aliasId);
  });

  it('should aliases generated with normalization', () => {
    const classicId = generateStandardId(ENTITY_TYPE_MALWARE, { name: 'SnowFlake' });
    const aliasId = generateAliasesId(['SnowFlake'], { name: 'APT28', entity_type: ENTITY_TYPE_MALWARE }).at(0);
    expect(classicId).toEqual('malware--1bc77052-c136-5258-b95d-fc8117fba3fd');
    expect(classicId).toEqual(aliasId);
  });

  it('should aliases filtered by rules', () => {
    const instance = { name: 'CVE-13', entity_type: ENTITY_TYPE_VULNERABILITY };
    const noAliasId = generateAliasesId(['951c8756-ee36-11ea-adc1-0242ac120002'], instance).at(0);
    expect(noAliasId).toBeUndefined();
    const aliasId = generateAliasesId(['CVE-2019-12345'], instance).at(0);
    expect(aliasId).toEqual('vulnerability--f140924c-f52e-5b3a-b8bb-37a97cee7063');
  });

  it('should stix id v5 always added', () => {
    const _2020_09_03T22_41_18 = 'v1--951c8756-ee36-11ea-adc1-0242ac120002';
    const _2020_09_03T22_41_32 = 'v1--9db69b68-ee36-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_00 = 'v1--a20665b0-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_43 = 'v1--bb896578-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T11_58_50 = 'v1--ff12cf7a-eea5-11ea-adc1-0242ac120002';
    const ids = cleanStixIds(
      [
        'indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf',
        'threat-actor--077b66a5-e64f-53df-bb22-03787ea16815',
        _2020_09_03T22_41_18,
        _2020_09_03T22_41_32,
        _2020_09_04T08_00_00,
        'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        _2020_09_04T08_00_43,
        'indicator--51640662-9c78-4402-932f-1d4531624723',
        _2020_09_04T11_58_50,
      ],
      5,
    );
    expect(ids.length).toEqual(9);
    expect(ids.includes(_2020_09_03T22_41_18)).toBeTruthy();
    expect(ids.includes('indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf')).toBeTruthy();
  });

  it('should stix id not added if existing', () => {
    // v1 to add
    const _2020_09_03T22_41_18 = 'v1--951c8756-ee36-11ea-adc1-0242ac120002';
    const ids = cleanStixIds(['indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf', _2020_09_03T22_41_18], 5);
    expect(ids.length).toEqual(2);
    expect(ids.includes(_2020_09_03T22_41_18)).toBeTruthy();
    expect(ids.includes('indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf')).toBeTruthy();
  });

  it('should stix id v1 correctly max sized', () => {
    // v1 to add
    const _2020_09_04T14_18_43 = 'v1--b709816c-eea8-11ea-adc1-0242ac120002';
    // existing v1 elements
    const _2020_09_03T22_41_18 = 'v1--951c8756-ee36-11ea-adc1-0242ac120002';
    const _2020_09_03T22_41_32 = 'v1--9db69b68-ee36-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_00 = 'v1--a20665b0-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_43 = 'v1--bb896578-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T11_58_50 = 'v1--ff12cf7a-eea5-11ea-adc1-0242ac120002';
    // 01. test add
    let ids = cleanStixIds(
      [
        _2020_09_04T14_18_43,
        'threat-actor--077b66a5-e64f-53df-bb22-03787ea16815',
        'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        'indicator--51640662-9c78-4402-932f-1d4531624723',
        _2020_09_04T08_00_43,
        _2020_09_04T11_58_50,
      ],
      2,
    );
    expect(ids.length).toEqual(5);
    expect(ids.includes('threat-actor--077b66a5-e64f-53df-bb22-03787ea16815')).toBeTruthy();
    expect(ids.includes(_2020_09_04T08_00_43)).toBeFalsy();
    expect(ids.includes(_2020_09_04T11_58_50)).toBeTruthy();
    expect(ids.includes(_2020_09_04T14_18_43)).toBeTruthy();
    // 02. test max 5
    ids = cleanStixIds(
      [
        _2020_09_04T14_18_43,
        'threat-actor--077b66a5-e64f-53df-bb22-03787ea16815',
        _2020_09_03T22_41_18,
        _2020_09_03T22_41_32,
        _2020_09_04T08_00_00,
        'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        _2020_09_04T08_00_43,
        'indicator--51640662-9c78-4402-932f-1d4531624723',
        _2020_09_04T11_58_50,
      ],
      5,
    );
    expect(ids.length).toEqual(8);
    expect(ids.includes('threat-actor--077b66a5-e64f-53df-bb22-03787ea16815')).toBeTruthy();
    expect(ids.includes('marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27')).toBeTruthy();
    expect(ids.includes('indicator--51640662-9c78-4402-932f-1d4531624723')).toBeTruthy();
    expect(ids.includes(_2020_09_03T22_41_18)).toBeFalsy(); // Oldest removed
    expect(ids.includes(_2020_09_03T22_41_32)).toBeTruthy();
    expect(ids.includes(_2020_09_04T08_00_00)).toBeTruthy();
    expect(ids.includes(_2020_09_04T08_00_43)).toBeTruthy();
    expect(ids.includes(_2020_09_04T14_18_43)).toBeTruthy();
    expect(ids.includes(_2020_09_04T11_58_50)).toBeTruthy();
  });

  it('should multi stix id correctly max sized', () => {
    // v1 to add
    const _2020_09_04T14_18_43 = 'v1--b709816c-eea8-11ea-adc1-0242ac120002';
    const _2020_09_04T14_39_43 = 'v1--b07d23fa-eeab-11ea-adc1-0242ac120002';
    // existing v1 elements
    const _2020_09_03T22_41_18 = 'v1--951c8756-ee36-11ea-adc1-0242ac120002';
    const _2020_09_03T22_41_32 = 'v1--9db69b68-ee36-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_00 = 'v1--a20665b0-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T08_00_43 = 'v1--bb896578-ee84-11ea-adc1-0242ac120002';
    const _2020_09_04T11_58_50 = 'v1--ff12cf7a-eea5-11ea-adc1-0242ac120002';
    // 01. test add
    const ids = cleanStixIds(
      [
        _2020_09_04T14_18_43,
        _2020_09_04T14_39_43,
        'threat-actor--077b66a5-e64f-53df-bb22-03787ea16815',
        'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        'indicator--51640662-9c78-4402-932f-1d4531624723',
        _2020_09_03T22_41_18,
        _2020_09_03T22_41_32,
        _2020_09_04T08_00_00,
        _2020_09_04T08_00_43,
        _2020_09_04T11_58_50,
      ],
      5,
    );
    expect(ids.length).toEqual(8);
    expect(ids.includes(_2020_09_04T14_18_43)).toBeTruthy();
    expect(ids.includes(_2020_09_04T14_39_43)).toBeTruthy();
    expect(ids.includes(_2020_09_03T22_41_18)).toBeFalsy();
    expect(ids.includes(_2020_09_03T22_41_32)).toBeFalsy();
  });

  it('should relation to input name', () => {
    let name = schemaRelationsRefDefinition.convertDatabaseNameToInputName(ENTITY_TYPE_CONTAINER_REPORT, 'object-marking');
    expect(name).toEqual('objectMarking');

    name = schemaRelationsRefDefinition.convertDatabaseNameToInputName(ENTITY_TYPE_CONTAINER_REPORT, 'object');
    expect(name).toEqual('objects');
  });

  it('should stix type converter_2_1 work', () => {
    const attackPattern = { type: 'attack-pattern' };
    const attackPatternType = generateInternalType(attackPattern);
    expect(attackPatternType).toEqual('Attack-Pattern');
    const courseOfAction = { type: 'course-of-action' };
    const courseOfActionType = generateInternalType(courseOfAction);
    expect(courseOfActionType).toEqual('Course-Of-Action');
    const indicator = { type: 'indicator' };
    const indicatorType = generateInternalType(indicator);
    expect(indicatorType).toEqual('Indicator');
    const identity = { type: 'identity', identity_class: 'individual' };
    const identityType = generateInternalType(identity);
    expect(identityType).toEqual('Individual');
    const location = { type: 'location', x_opencti_location_type: 'Country' };
    const locationType = generateInternalType(location);
    expect(locationType).toEqual('Country');
    const ipv4 = { type: 'ipv4-addr' };
    const ipv4Type = generateInternalType(ipv4);
    expect(ipv4Type).toEqual('IPv4-Addr');
    const hostname = { type: 'hostname' };
    const hostnameType = generateInternalType(hostname);
    expect(hostnameType).toEqual('Hostname');
  });
});
