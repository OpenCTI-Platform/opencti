import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { v5 as uuidv5 } from 'uuid';
import jsonCanonicalize from 'canonicalize';
import '../../../src/modules/index';
import { generateStandardId, getIdentifierContributions, idGen, MARKING_TLP_CLEAR_ID, registerModelIdentifier, resolveContribution } from '../../../src/schema/identifier';
import { OASIS_NAMESPACE, OPENCTI_NAMESPACE } from '../../../src/schema/general';
import { DatabaseError, FunctionalError, UnsupportedError } from '../../../src/config/errors';
import { convertTypeToStixType } from '../../../src/database/stix-2-1-converter';
import { isStixMetaObject } from '../../../src/schema/stixMetaObject';
import { isStixDomainObject } from '../../../src/schema/stixDomainObject';
import { isStixCyberObservable } from '../../../src/schema/stixCyberObservable';
import { isInternalObject } from '../../../src/schema/internalObject';
import { isInternalRelationship } from '../../../src/schema/internalRelationship';
import { isStixRefRelationship } from '../../../src/schema/stixRefRelationship';
import { isStixCoreRelationship } from '../../../src/schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../../../src/schema/stixSightingRelationship';

// region reference: the standard id chain before the native rewrite (src/schema/identifier.js @b48f3c0250)
const isNotEmptyFieldReference = (field) => !R.isEmpty(field) && !R.isNil(field);
const isEmptyFieldReference = (field) => !isNotEmptyFieldReference(field);
const STATIC_STANDARD_IDS_REFERENCE = [
  { id: MARKING_TLP_CLEAR_ID, data: { definition_type: 'TLP', definition: 'TLP:WHITE' } },
  { id: MARKING_TLP_CLEAR_ID, data: { definition_type: 'TLP', definition: 'TLP:CLEAR' } },
  { id: '34098fce-860f-48ae-8e50-ebd3cc5e41da', data: { definition_type: 'TLP', definition: 'TLP:GREEN' } },
  { id: 'f88d31f6-486f-44da-b317-01333bde0b82', data: { definition_type: 'TLP', definition: 'TLP:AMBER' } },
  { id: '826578e1-40ad-459f-bc73-ede076f81f37', data: { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' } },
  { id: '5e57c739-391a-4eb3-b6be-7d15ca92d5ed', data: { definition_type: 'TLP', definition: 'TLP:RED' } },
];
const getStaticIdFromDataReference = (data) => {
  const findStatic = R.find((s) => R.equals(s.data, data), STATIC_STANDARD_IDS_REFERENCE);
  return findStatic?.id;
};
const resolveContributionReference = (type) => {
  const finder = (c) => Object.keys(c.definition).includes(type);
  const ident = getIdentifierContributions().find(finder);
  if (!ident) {
    throw UnsupportedError(`Type ${type} has not available resolution`);
  }
  return ident;
};
const idGenReference = (type, data, namespace) => {
  if (isEmptyFieldReference(data)) {
    const contrib = resolveContributionReference(type);
    const properties = contrib.definition[type].flat();
    const missingKeys = properties.flat().map((p) => p.src).join(' - ');
    throw FunctionalError(`Missing required elements for ${type} creation (${missingKeys})`, { properties });
  }
  const findStaticId = getStaticIdFromDataReference(data);
  if (findStaticId) {
    return findStaticId;
  }
  const dataCanonicalize = jsonCanonicalize(data);
  return uuidv5(dataCanonicalize, namespace);
};
const filteredIdContributionsReference = (contrib, way, data) => {
  const propertiesToKeep = R.flatten(R.map((t) => t.src, way));
  const dataRelated = R.pick(propertiesToKeep, data);
  if (R.isEmpty(dataRelated)) {
    return {};
  }
  const objectData = {};
  const entries = Object.entries(dataRelated);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const [key, value] = entry;
    const prop = R.find((e) => R.includes(key, e.src), way);
    const { src, dest, dependencies = [] } = prop;
    const dataDependencies = Object.values(R.pickAll(dependencies, data));
    const isEmptyValueInDependencies = dataDependencies.filter((n) => isEmptyFieldReference(n)).length !== 0;
    if (isEmptyValueInDependencies) {
      return {};
    }
    const destKey = dest || src;
    const resolver = contrib.resolvers[src];
    if (resolver) {
      objectData[destKey] = value ? resolver(value, data) : value;
    } else {
      objectData[destKey] = R.is(String, value) ? value.trim() : value;
    }
  }
  return R.filter((keyValue) => !R.isEmpty(keyValue) && !R.isNil(keyValue), objectData);
};
const generateDataUUIDReference = (type, input) => {
  const data = { ...input, opencti_type: type };
  const contrib = resolveContributionReference(type);
  const properties = contrib.definition[type];
  if (!properties) {
    throw DatabaseError(`Unknown definition for type ${type}`);
  }
  if (!Array.isArray(properties)) {
    return { data: properties(), way: properties };
  }
  if (properties.length === 0) {
    return { data, way: properties };
  }
  const dataWay = {};
  const haveDiffWays = Array.isArray(R.head(properties));
  if (haveDiffWays) {
    for (let index = 0; index < properties.length; index += 1) {
      const way = properties[index];
      const uuid = filteredIdContributionsReference(contrib, way, data);
      if (!R.isEmpty(uuid)) {
        dataWay.way = way;
        dataWay.data = uuid;
        break;
      }
    }
  } else {
    dataWay.way = properties;
    dataWay.data = filteredIdContributionsReference(contrib, properties, data);
  }
  return dataWay;
};
const generateStixIdReference = (type, data) => {
  const { data: dataUUID } = generateDataUUIDReference(type, data);
  return `${convertTypeToStixType(type)}--${idGenReference(type, dataUUID, OASIS_NAMESPACE)}`;
};
const generateObjectIdReference = (type, data) => {
  const { data: dataUUID } = generateDataUUIDReference(type, data);
  return `${convertTypeToStixType(type)}--${idGenReference(type, dataUUID, OPENCTI_NAMESPACE)}`;
};
const generateStandardIdReference = (type, data) => {
  if (isStixMetaObject(type)) return generateStixIdReference(type, data);
  if (isStixDomainObject(type)) return generateStixIdReference(type, data);
  if (isStixCyberObservable(type)) return generateStixIdReference(type, data);
  if (isInternalObject(type)) return generateObjectIdReference(type, data);
  if (isInternalRelationship(type) || isStixRefRelationship(type)) throw new Error('random id, not compared');
  if (isStixCoreRelationship(type)) return generateStixIdReference('relationship', data);
  if (isStixSightingRelationship(type)) return generateStixIdReference('sighting', data);
  throw UnsupportedError(`${type} is not supported by the platform`);
};
// endregion

const outcome = (fn) => {
  try {
    return { value: fn() };
  } catch (err) {
    return { error: err.constructor.name, name: err.name, message: err.message };
  }
};
const expectSameOutcome = (fn, referenceFn, label) => {
  expect(outcome(fn), label).toStrictEqual(outcome(referenceFn));
};

// region generated inputs: every src of every registered contribution
const STRINGS = ['  Mixed Case Value ', 'évènement ü', 'emoji 😀 𝒳 astral', 'tab\tand\nnewline', 'T1059', '   ', ''];
const flatSrcs = (properties) => R.flatten(properties).map((p) => p.src);
const valueForSrc = (src, variant) => {
  const text = STRINGS[variant % STRINGS.length];
  switch (src) {
    case 'from':
    case 'to':
    case 'src':
    case 'dst':
      return variant % 3 === 2 ? {} : { standard_id: `malware--${variant}a6f5e4c-1d2b-4e8f-9a7c-${String(variant).padStart(12, '0')}` };
    case 'hashes':
      return [{ md5: 'AbC' }, { 'SHA-256': 'f'.repeat(64), MD5: 'm' }, { 'sha-1': 's1' }, {}, { unknown: 'x' }, { SSDEEP: '3:a:b' }, { TLSH: 't' }][variant % 7];
    case 'objects':
      return [{ standard_id: `report--${variant}` }, { standard_id: 'a--1' }];
    case 'published':
    case 'created':
    case 'first_observed':
    case 'last_observed':
    case 'timestamp':
    case 'start':
    case 'end':
    case 'first_seen':
    case 'last_seen':
    case 'start_time':
    case 'stop_time':
      return variant % 2 === 0 ? new Date(1700000000000 + variant * 1000) : `2024-01-0${1 + (variant % 9)}T00:00:00.000Z`;
    case 'number':
    case 'pid':
    case 'src_port':
    case 'dst_port':
    case 'latitude':
    case 'longitude':
      return [0, 443, '12', 48.85, -2][variant % 5];
    case 'protocols':
    case 'values':
      return variant % 3 === 0 ? [] : ['tcp', ` ${text}`];
    case 'definition_type':
      return ['TLP', 'tlp', 'PAP', 'statement'][variant % 4];
    case 'definition':
      return ['TLP:CLEAR', 'tlp:white', 'TLP:AMBER+STRICT', 'PAP:RED', 'TLP:RED', 'custom'][variant % 6];
    default:
      return variant % 11 === 10 ? null : `${text}${variant > 6 ? ` ${variant}` : ''}`;
  }
};
const buildInputs = (properties) => {
  const srcs = R.uniq(flatSrcs(properties));
  const inputs = [];
  for (let variant = 0; variant < 14; variant += 1) {
    // All the contributing fields set
    inputs.push(Object.fromEntries(srcs.map((src) => [src, valueForSrc(src, variant)])));
    // Each contributing field alone
    srcs.forEach((src) => inputs.push({ [src]: valueForSrc(src, variant), description: 'not contributing' }));
    // Each contributing field removed, then emptied (dependencies)
    srcs.forEach((src) => {
      const full = Object.fromEntries(srcs.map((s) => [s, valueForSrc(s, variant)]));
      inputs.push(R.dissoc(src, full));
      inputs.push({ ...full, [src]: ['', null, undefined][variant % 3] });
    });
  }
  inputs.push({}, { name: undefined }, { description: 'nothing contributing' });
  return inputs;
};
const typeUnderTest = (type) => {
  if (type === 'relationship') return 'uses';
  if (type === 'sighting') return 'stix-sighting-relationship';
  return type;
};
// endregion

describe('standard id generation equivalence with the ramda implementation', () => {
  it('should generate the same ids for every registered type and input shape', () => {
    let compared = 0;
    let generated = 0;
    getIdentifierContributions().forEach((contrib) => {
      Object.entries(contrib.definition).forEach(([type, properties]) => {
        if (!Array.isArray(properties)) return; // dedicated generation function, often random
        buildInputs(properties).forEach((input) => {
          const target = typeUnderTest(type);
          expectSameOutcome(() => generateStandardId(target, input), () => generateStandardIdReference(target, input), `${type} ${JSON.stringify(input)}`);
          compared += 1;
          if (outcome(() => generateStandardId(target, input)).value) generated += 1;
        });
      });
    });
    expect(compared).toBeGreaterThan(5000);
    // Most shapes produce an id, the others throw the same error on both sides
    expect(generated / compared).toBeGreaterThan(0.5);
  });

  it.each([
    ['Marking-Definition', { definition_type: 'TLP', definition: 'TLP:CLEAR' }],
    ['Marking-Definition', { definition_type: 'tlp', definition: 'tlp:white', x_opencti_order: 1 }],
    ['Marking-Definition', { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' }],
    ['Marking-Definition', { definition_type: 'PAP', definition: 'PAP:RED' }],
    ['Marking-Definition', { definition_type: 'TLP', definition: 'TLP:UNKNOWN' }],
    ['Attack-Pattern', { x_mitre_id: 'T1059', name: 'Command' }],
    ['Attack-Pattern', { name: 'Only name' }],
    ['Attack-Pattern', { x_mitre_id: '', name: 'Empty mitre id' }],
    ['External-Reference', { url: 'https://attack.mitre.org/techniques/T1059 ', source_name: 'mitre-attack', external_id: 'T1059' }],
    ['External-Reference', { source_name: 'cve', external_id: 'CVE-2024-1' }],
    ['External-Reference', { source_name: 'cve', external_id: '' }, true],
    ['Label', { value: ' Mixed Case ' }],
    ['Malware', { name: 'astral 𝕏 😀 name' }],
    ['Malware', { name: 'a'.repeat(2000) }],
    ['Software', { name: 'SoftWare', vendor: 'Vendor' }],
    ['StixFile', { name: 'File.EXE', hashes: { 'sha-256': 'a'.repeat(64) } }],
    ['Report', { name: 'Report', published: new Date('2024-01-01T00:00:00.000Z') }],
  ])('should generate the same id for %s %j', (type, input, throws = false) => {
    expectSameOutcome(() => generateStandardId(type, input), () => generateStandardIdReference(type, input), type);
    expect(outcome(() => generateStandardId(type, input)).error !== undefined).toBe(throws);
  });

  it.each([
    ['substring src match', [{ src: 'persona_name' }, { src: 'name' }], { name: 'Name', persona_name: 'Persona' }],
    ['substring src match with dest', [{ src: 'persona_name', dest: 'p' }, { src: 'name', dest: 'n' }], { name: 'Name' }],
    ['array src', [{ src: ['name', 'alias'] }, { src: 'description' }], { alias: 'Alias', name: 'Name', description: ' d ' }],
    ['integer like srcs', [{ src: 'name' }, { src: '1' }, { src: '0' }], { 0: 'zero', 1: 'one', name: 'Name' }],
    ['duplicated src', [{ src: 'name' }, { src: 'name', dest: 'other' }], { name: 'Name' }],
    ['string dependencies', [{ src: 'name', dependencies: 'ab' }], { name: 'Name', a: 'x', b: '' }],
    ['undefined src value with an empty dependency', [{ src: 'name' }, { src: 'alias', dependencies: ['x'] }], { name: 'Name', alias: undefined, x: '' }],
    ['inherited src', [{ src: 'toString' }, { src: 'name' }], { name: 'Name' }],
    ['different ways', [[{ src: 'x_mitre_id' }], [{ src: 'name', dependencies: ['x'] }], [{ src: 'name' }]], { name: 'Name', x: '' }],
  ])('should generate the same id with a synthetic definition: %s', (label, way, input) => {
    const contrib = resolveContribution('Malware');
    const original = contrib.definition.Malware;
    contrib.definition.Malware = way;
    try {
      expectSameOutcome(() => generateStandardId('Malware', input), () => generateStandardIdReference('Malware', input), JSON.stringify(way));
      const throws = ['undefined src value with an empty dependency', 'string dependencies'].includes(label);
      expect(outcome(() => generateStandardId('Malware', input)).error !== undefined).toBe(throws);
    } finally {
      contrib.definition.Malware = original;
    }
  });

  it('should return the community static ids of the TLP markings', () => {
    expect(generateStandardId('Marking-Definition', { definition_type: 'tlp', definition: 'tlp:white' })).toBe(`marking-definition--${MARKING_TLP_CLEAR_ID}`);
  });

  it('should throw the same error on a lone surrogate', () => {
    // canonicalize rejects it before uuid v5 (which would throw an URIError)
    const input = { name: 'lone \ud800 surrogate' };
    expect(outcome(() => generateStandardId('Malware', input)).error).toBeDefined();
    expectSameOutcome(() => generateStandardId('Malware', input), () => generateStandardIdReference('Malware', input), 'lone surrogate');
    expectSameOutcome(() => generateStandardId('Malware', input), () => generateStandardIdReference('Malware', input), 'lone surrogate again');
  });

  it('should keep idGen identical on random unicode data, past the memo bound', () => {
    let seed = 7;
    const random = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const values = [];
    for (let i = 0; i < 21000; i += 1) {
      const codePoints = Array.from({ length: 1 + (i % 40) }, () => Math.floor(random() * 0x10ffff));
      values.push({ name: `${i} ${String.fromCodePoint(...codePoints)}` });
    }
    values.push({ name: 'x'.repeat(600) }); // above the memo string bound
    // Twice: the second pass reads the memo for the values kept after the overflow
    for (let pass = 0; pass < 2; pass += 1) {
      values.forEach((data) => {
        expectSameOutcome(() => idGen('Malware', data, OASIS_NAMESPACE), () => idGenReference('Malware', data, OASIS_NAMESPACE), JSON.stringify(data));
        expectSameOutcome(() => idGen('Malware', data, OPENCTI_NAMESPACE), () => idGenReference('Malware', data, OPENCTI_NAMESPACE), JSON.stringify(data));
      });
    }
    expectSameOutcome(() => idGen('Malware', {}, OASIS_NAMESPACE), () => idGenReference('Malware', {}, OASIS_NAMESPACE), 'empty');
    expectSameOutcome(() => idGen('Malware', 'raw string', OASIS_NAMESPACE), () => idGenReference('Malware', 'raw string', OASIS_NAMESPACE), 'string');
    expectSameOutcome(() => idGen('Malware', { name: 'x' }, 'not-a-uuid'), () => idGenReference('Malware', { name: 'x' }, 'not-a-uuid'), 'bad namespace');
  });

  it('should resolve the same contribution, not keep misses, and reset on registration', () => {
    getIdentifierContributions().forEach((contrib) => {
      Object.keys(contrib.definition).forEach((type) => {
        expect(resolveContribution(type)).toBe(resolveContributionReference(type));
        expect(resolveContribution(type)).toBe(resolveContributionReference(type)); // cached
      });
    });
    expect(() => resolveContribution('X-Oracle-Late-Type')).toThrow('Type X-Oracle-Late-Type has not available resolution');
    expect(() => resolveContribution('X-Oracle-Late-Type')).toThrow('Type X-Oracle-Late-Type has not available resolution');
    const lateContribution = { definition: { 'X-Oracle-Late-Type': [{ src: 'name' }], Malware: [{ src: 'other' }] }, resolvers: {} };
    const malwareContribution = resolveContribution('Malware');
    registerModelIdentifier(lateContribution);
    expect(resolveContribution('X-Oracle-Late-Type')).toBe(lateContribution);
    expect(resolveContribution('Malware')).toBe(malwareContribution); // first registered still wins
    expect(resolveContribution('Malware')).toBe(resolveContributionReference('Malware'));
    expect(outcome(() => idGen('X-Oracle-Late-Type', {}, OASIS_NAMESPACE)))
      .toStrictEqual(outcome(() => idGenReference('X-Oracle-Late-Type', {}, OASIS_NAMESPACE)));
  });
});
