import { describe, expect, it } from 'vitest';
import { generateAliasesIdsForInstance, generateStandardId, idGen, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_DOMAIN_NAME, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';
import { RELATION_INDICATES, RELATION_USES } from '../../../src/schema/stixCoreRelationship';

const from = { standard_id: 'intrusion-set--9e87a4d3-6a3d-5b56-8c3b-1c1f0e7c3f00', entity_type: ENTITY_TYPE_INTRUSION_SET };
const to = { standard_id: 'malware--0c3a1e3e-4f1b-5c7a-9a0e-2d4b6f8a1c00', entity_type: ENTITY_TYPE_MALWARE };

// Inputs covering the id contributions (names, aliases, observables, hashes, relationships with and without
// time, markings with static ids), with the ids the implementation produced before its fast paths were added
const cases: [string, string, Record<string, any>, string][] = [
  ['intrusion set', ENTITY_TYPE_INTRUSION_SET, { name: 'APT28' }, ''],
  ['intrusion set, padded name', ENTITY_TYPE_INTRUSION_SET, { name: '  APT28  ' }, ''],
  ['malware', ENTITY_TYPE_MALWARE, { name: 'X-Agent' }, ''],
  ['attack pattern with external id', ENTITY_TYPE_ATTACK_PATTERN, { name: 'Phishing', x_mitre_id: 'T1566' }, ''],
  ['domain name', ENTITY_DOMAIN_NAME, { value: 'example.com' }, ''],
  ['ipv4', ENTITY_IPV4_ADDR, { value: '10.0.0.1' }, ''],
  ['file with hashes', ENTITY_HASHED_OBSERVABLE_STIX_FILE, { hashes: { 'SHA-256': 'a'.repeat(64), MD5: 'b'.repeat(32) } }, ''],
  ['file with empty hash', ENTITY_HASHED_OBSERVABLE_STIX_FILE, { name: 'a.exe', hashes: { MD5: '' } }, ''],
  ['uses', RELATION_USES, { relationship_type: RELATION_USES, from, to }, ''],
  ['uses with time', RELATION_USES, { relationship_type: RELATION_USES, from, to, start_time: '2024-01-01T00:00:00.000Z', stop_time: '2024-02-01T00:00:00.000Z' }, ''],
  ['indicates', RELATION_INDICATES, { relationship_type: RELATION_INDICATES, from, to }, ''],
  ['TLP:GREEN', ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'TLP', definition: 'TLP:GREEN' }, MARKING_TLP_GREEN],
  ['TLP:WHITE', ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'TLP', definition: 'TLP:WHITE' }, MARKING_TLP_CLEAR],
  ['TLP:RED', ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'TLP', definition: 'TLP:RED' }, MARKING_TLP_RED],
  ['PAP marking', ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'PAP', definition: 'PAP:GREEN' }, ''],
  ['TLP-like marking, other definition', ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'TLP', definition: 'TLP:PURPLE' }, ''],
];

describe('generateStandardId', () => {
  it.each(cases)('keeps the standard id of %s', (_label, type, data, expected) => {
    const id = generateStandardId(type, data);
    if (expected) expect(id).toBe(expected);
    expect(id).toMatchSnapshot();
  });
  it('finds static ids whatever the key order, and only for exact data', () => {
    expect(idGen(ENTITY_TYPE_MARKING_DEFINITION, { definition: 'TLP:GREEN', definition_type: 'TLP' }, 'ns')).toBe(MARKING_TLP_GREEN.split('--')[1]);
    expect(idGen(ENTITY_TYPE_MARKING_DEFINITION, Object.assign(Object.create(null), { definition_type: 'TLP', definition: 'TLP:GREEN' }), 'ns'))
      .toBe(MARKING_TLP_GREEN.split('--')[1]);
    expect(idGen(ENTITY_TYPE_MARKING_DEFINITION, { definition_type: 'TLP', definition: 'TLP:GREEN', x: 1 }, '6ba7b810-9dad-11d1-80b4-00c04fd430c8'))
      .not.toBe(MARKING_TLP_GREEN.split('--')[1]);
  });
  it('keeps alias ids', () => {
    const ids = generateAliasesIdsForInstance({ entity_type: ENTITY_TYPE_INTRUSION_SET, name: 'APT28', aliases: ['Fancy Bear', ' Sofacy ', ''] });
    expect(ids).toMatchSnapshot();
  });
});
