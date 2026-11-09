import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as R from 'ramda';
import '../../../src/modules/index';
import * as cacheModule from '../../../src/database/cache';
import { buildEntityData, buildInnerRelation } from '../../../src/database/data-builder';
import { BASE_TYPE_ENTITY, ID_INTERNAL, ID_STANDARD, IDS_STIX, INTERNAL_IDS_ALIASES } from '../../../src/schema/general';
import { getParentTypes } from '../../../src/schema/schemaUtils';
import { generateAliasesIdsForInstance, generateInternalId, generateStandardId, MARKING_TLP_CLEAR, normalizeName, X_WORKFLOW_ID } from '../../../src/schema/identifier';
import { now } from '../../../src/utils/format';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { ENTITY_TYPE_STATUS, isDatedInternalObject } from '../../../src/schema/internalObject';
import { isStixObject } from '../../../src/schema/stixCoreObject';
import { isStixMetaObject } from '../../../src/schema/stixMetaObject';
import { isStixDomainObject, isStixObjectAliased, resolveAliasesField, STIX_ORGANIZATIONS_RESTRICTED, STIX_ORGANIZATIONS_UNRESTRICTED } from '../../../src/schema/stixDomainObject';
import { isServiceAccountUser, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from '../../../src/utils/access';
import { cleanMarkings } from '../../../src/utils/markingDefinition-utils';
import { pushAll } from '../../../src/utils/arrayUtil';
import { ADMIN_USER } from '../../utils/testQuery';

// Deterministic uuid v4 (internal ids of the entity and of its meta relationships), reset before each side
const uuidState = vi.hoisted(() => ({ counter: 0 }));
vi.mock('uuid', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    v4: () => {
      uuidState.counter += 1;
      return `00000000-0000-4000-8000-${String(uuidState.counter).padStart(12, '0')}`;
    },
  };
});

// Reference: the ramda based helpers and buildEntityData before the copy chain rewrite (@b48f3c0250)
const isNotEmptyField = (field) => !R.isEmpty(field) && !R.isNil(field);
const buildEntityDataReference = async (context, user, input, type, opts = {}) => {
  const { fromRule, restore } = opts;
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(type, input);
  // Complete with identifiers
  const today = now();
  const inferred = isNotEmptyField(fromRule);
  // Default attributes
  let data = R.pipe(
    R.assoc('_index', inferIndexFromConceptType(type, inferred)),
    R.assoc(ID_INTERNAL, internalId),
    R.assoc(ID_STANDARD, standardId),
    R.assoc('entity_type', type),
    R.assoc('creator_id', [user.internal_id]),
    R.dissoc('update'),
    R.dissoc('upsertOperations'),
    R.dissoc('file'),
    R.dissoc('fileMarkings'),
    R.dissoc('files'),
    R.dissoc('filesMarkings'),
    R.dissoc('noTriggerImport'),
    R.dissoc('embedded'),
    R.omit(schemaRelationsRefDefinition.getInputNames(input.entity_type)),
  )(input);
  if (inferred) {
    // Simply add the rule
    // start/stop confidence was computed by the rule directly
    data[fromRule] = input[fromRule];
  }
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = R.pipe(
      R.assoc('created_at', restore ? input.created : today),
      R.assoc('updated_at', today),
    )(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data = R.pipe(
      R.assoc(IDS_STIX, stixIds),
      R.dissoc('stix_id'),
      R.assoc('created_at', today),
      R.assoc('updated_at', today),
      R.assoc('refreshed_at', today),
    )(data);
  }
  // Stix-Meta-Object
  if (isStixMetaObject(type)) {
    data = R.pipe(
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified),
    )(data);
  }
  // STIX-Core-Object
  // -- STIX-Domain-Object
  if (isStixDomainObject(type)) {
    data = R.pipe(
      R.assoc('revoked', R.isNil(input.revoked) ? false : input.revoked),
      R.assoc('confidence', R.isNil(input.confidence) ? 0 : input.confidence),
      R.assoc('lang', R.isNil(input.lang) ? 'en' : input.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified),
    )(data);
    // Get statuses
    const platformStatuses = await cacheModule.getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
    const statusesForType = platformStatuses.filter((p) => p.type === type);
    if (statusesForType.length > 0) {
      // Check, if status is not set or not valid
      if (R.isNil(input[X_WORKFLOW_ID]) || statusesForType.filter((n) => n.id === input[X_WORKFLOW_ID]).length === 0) {
        data = R.assoc(X_WORKFLOW_ID, R.head(statusesForType).id, data);
      }
    }
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    const aliasField = resolveAliasesField(type).name;
    if (input[aliasField]) {
      const preparedAliases = input[aliasField].filter((a) => isNotEmptyField(a)).map((a) => a.trim());
      const uniqAliases = R.uniqBy((e) => normalizeName(e), preparedAliases);
      data[aliasField] = uniqAliases.filter((e) => normalizeName(e) !== normalizeName(input.name));
    }
    const aliasIds = generateAliasesIdsForInstance(data);
    data[INTERNAL_IDS_ALIASES] = aliasIds;
    // Do not cumulate alias standard IDs in other STIX IDs
    if (data[IDS_STIX]) {
      data[IDS_STIX] = data[IDS_STIX].filter((id) => !aliasIds.includes(id));
    }
  }
  // Create the meta relationships (ref, refs)
  const relToCreate = [];
  const isSegregationEntity = !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(data.entity_type).includes(o))
    || STIX_ORGANIZATIONS_RESTRICTED.some((o) => o === data.entity_type || getParentTypes(data.entity_type).includes(o));
  const appendMetaRelationships = async (inputField, relType) => {
    if (input[inputField] || relType === RELATION_GRANTED_TO) {
      // For organizations management
      if (relType === RELATION_GRANTED_TO && isSegregationEntity) {
        if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && input[inputField]
          && (!Array.isArray(input[inputField]) || input[inputField].length > 0)) {
          pushAll(relToCreate, buildInnerRelation(data, input[inputField], RELATION_GRANTED_TO));
        } else if (!context.user_inside_platform_organization || (isServiceAccountUser(user) && isNotEmptyField(user.organizations))) {
          // If user is not part of the platform organization or is a service account with organizations, put its own organizations
          pushAll(relToCreate, buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
        }
      } else if (relType === RELATION_OBJECT_MARKING) {
        const markingsFiltered = await cleanMarkings(context, input[inputField]);
        pushAll(relToCreate, buildInnerRelation(data, markingsFiltered, relType));
      } else if (input[inputField]) {
        const instancesToCreate = Array.isArray(input[inputField]) ? input[inputField] : [input[inputField]];
        pushAll(relToCreate, buildInnerRelation(data, instancesToCreate, relType));
      }
    }
  };
  // For meta stix core && meta observables
  const inputFields = schemaRelationsRefDefinition.getRelationsRef(input.entity_type);
  for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
    const inputField = inputFields[fieldIndex];
    await appendMetaRelationships(inputField.name, inputField.databaseName);
  }

  // Transaction succeed, complete the result to send it back
  const entity = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type)),
  )(data);

  // Simply return the data
  return {
    isCreation: true,
    element: entity,
    previous: null,
    relations: relToCreate, // Added meta relationships
  };
};

// region inputs
const MARKINGS = [
  { id: 'm-clear', internal_id: 'm-clear', standard_id: MARKING_TLP_CLEAR, entity_type: 'Marking-Definition', definition_type: 'TLP', definition: 'TLP:CLEAR', x_opencti_order: 1 },
  { id: 'm-red', internal_id: 'm-red', standard_id: 'marking-definition--red', entity_type: 'Marking-Definition', definition_type: 'TLP', definition: 'TLP:RED', x_opencti_order: 4 },
  { id: 'm-pap', internal_id: 'm-pap', standard_id: 'marking-definition--pap', entity_type: 'Marking-Definition', definition_type: 'PAP', definition: 'PAP:RED', x_opencti_order: 3 },
];
const STATUSES = [
  { id: 'status-malware-1', type: 'Malware' },
  { id: 'status-malware-2', type: 'Malware' },
  { id: 'status-report-1', type: 'Report' },
];
const ref = (entityType, name) => ({ id: `${name}-id`, internal_id: `${name}-id`, standard_id: `${entityType.toLowerCase()}--${name}`, entity_type: entityType, name });
const ORGANIZATIONS = [ref('Organization', 'org-a'), ref('Organization', 'org-b')];
const META = {
  createdBy: ref('Organization', 'author'),
  objectMarking: MARKINGS,
  objectLabel: [ref('Label', 'label-a'), ref('Label', 'label-b')],
  externalReferences: [ref('External-Reference', 'ext-a')],
  killChainPhases: [ref('Kill-Chain-Phase', 'kcp-a')],
  objectOrganization: [ORGANIZATIONS[0]],
};
const NOT_STORED = { update: true, upsertOperations: [], file: { name: 'f' }, fileMarkings: ['m'], files: [{ name: 'g' }], filesMarkings: ['n'], noTriggerImport: true, embedded: false };
const shuffle = (obj, seed) => {
  const keys = Object.keys(obj);
  const out = {};
  keys.map((k, i) => [k, (i * 7919 + seed * 104729) % 1009]).sort((a, b) => a[1] - b[1]).forEach(([k]) => {
    out[k] = obj[k];
  });
  return out;
};
// Each factory builds a fresh input: buildEntityData mutates input.x_opencti_stix_ids
const BASE_INPUTS = [
  ['Malware', () => ({ name: 'Emotet', description: 'd', aliases: ['emotet', ' Geodo ', '', 'GEODO', 'Heodo'], confidence: 80, ...META })],
  ['Malware', () => ({ name: 'NoMeta', x_opencti_workflow_id: 'status-malware-2', revoked: true, lang: 'fr', created: '2020-01-01T00:00:00.000Z' })],
  ['Malware', () => ({ name: 'BadWorkflow', x_opencti_workflow_id: 'unknown', stix_id: 'Malware--ABC', x_opencti_stix_ids: ['malware--old'], ...NOT_STORED })],
  ['Malware', () => ({ internal_id: 'given-internal', standard_id: 'malware--given', name: 'Given ids', stix_id: 'malware--given', confidence: 0, revoked: null })],
  ['Intrusion-Set', () => ({ name: 'APT', aliases: ['apt-x'], x_opencti_aliases: ['other'], objectMarking: [MARKINGS[1]], createdBy: META.createdBy })],
  ['Threat-Actor-Group', () => ({ name: 'Group', aliases: [] })],
  ['Report', () => ({ name: 'Report', published: '2024-01-01T00:00:00.000Z', objects: [ref('Malware', 'obj-a'), ref('Indicator', 'obj-b')], report_types: ['threat-report'], ...META })],
  ['Indicator', () => ({ name: 'ind', pattern: "[ipv4-addr:value = '1.1.1.1']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr', valid_from: new Date('2024-01-01T00:00:00.000Z'), x_opencti_score: 50, objectMarking: MARKINGS })],
  ['Attack-Pattern', () => ({ name: 'Command', x_mitre_id: 'T1059', killChainPhases: META.killChainPhases, x_mitre_platforms: ['linux'] })],
  ['Vulnerability', () => ({ name: 'CVE-2024-0001', x_opencti_cvss_base_score: 9.8, externalReferences: META.externalReferences })],
  ['Label', () => ({ value: 'label', color: '#fff' })],
  ['Marking-Definition', () => ({ definition_type: 'TLP', definition: 'TLP:GREEN', x_opencti_order: 2, x_opencti_color: '#0f0', created: null, modified: '2023-01-01T00:00:00.000Z' })],
  ['External-Reference', () => ({ source_name: 'mitre', external_id: 'T1', url: 'https://example.com', fileMarkings: [] })],
  ['Kill-Chain-Phase', () => ({ kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 1 })],
  ['IPv4-Addr', () => ({ value: '10.0.0.1', x_opencti_score: 40, createdBy: META.createdBy, objectLabel: META.objectLabel })],
  ['Domain-Name', () => ({ value: 'example.com', objectMarking: [] })],
  ['StixFile', () => ({ name: 'file.exe', hashes: { MD5: 'a'.repeat(32), 'SHA-256': 'b'.repeat(64) }, x_opencti_additional_names: ['f.exe'] })],
  ['Group', () => ({ name: 'Group', description: 'g', default_assignation: false, auto_new_marking: true })],
  ['Role', () => ({ name: 'Role', description: 'r' })],
  ['StatusTemplate', () => ({ name: 'NEW', color: '#000' })],
  ['Organization', () => ({ name: 'Org', x_opencti_aliases: ['ORG', 'org', ' o '], objectOrganization: ORGANIZATIONS })],
];
const buildCases = () => {
  const cases = [];
  BASE_INPUTS.forEach(([type, baseFactory], index) => {
    const factory = () => ({ entity_type: type, ...baseFactory() });
    cases.push([`${type} #${index}`, type, factory, {}]);
    cases.push([`${type} #${index} shuffled`, type, () => shuffle(factory(), index + 1), {}]);
    // Only the domain objects have an inferred index
    if (isStixDomainObject(type)) cases.push([`${type} #${index} inferred`, type, () => ({ ...factory(), 'i_rule_test-rule': [{ explanation: ['a'] }] }), { fromRule: 'i_rule_test-rule' }]);
    cases.push([`${type} #${index} restore`, type, () => ({ ...factory(), created: '2021-01-01T00:00:00.000Z' }), { restore: true }]);
    cases.push([`${type} #${index} inherited`, type, () => Object.assign(Object.create({ inherited_field: 'from proto', name: 'shadowed' }), factory()), {}]);
    cases.push([`${type} #${index} integer keys`, type, () => ({ 2: 'two', ...factory(), 1: 'one' }), {}]);
    cases.push([`${type} #${index} with connections key`, type, () => ({ connections: ['kept'], ...factory() }), {}]);
  });
  // Own __proto__ key (JSON.parse creates it as a data property), simple and nested
  cases.push(['Malware own __proto__', 'Malware', () => JSON.parse('{"entity_type":"Malware","name":"Proto","__proto__":{"polluted":"p","name":"inner"},"description":"d"}'), {}]);
  cases.push(['Malware nested __proto__', 'Malware', () => JSON.parse('{"entity_type":"Malware","name":"Proto2","__proto__":{"a":1,"__proto__":{"b":2}},"description":"d"}'), {}]);
  cases.push(['Malware null __proto__', 'Malware', () => JSON.parse('{"entity_type":"Malware","name":"Proto3","__proto__":null}'), {}]);
  return cases;
};
// endregion

const USERS = [
  ['admin inside platform organization', ADMIN_USER, { user_inside_platform_organization: true }],
  ['admin outside platform organization', ADMIN_USER, { user_inside_platform_organization: false }],
  ['user with organizations outside', { ...ADMIN_USER, internal_id: 'user-2', capabilities: [], organizations: ORGANIZATIONS }, { user_inside_platform_organization: false }],
];
const run = async (fn, context, user, factory, type, opts) => {
  uuidState.counter = 0;
  const input = factory();
  try {
    const result = await fn(context, user, input, type, opts);
    return { result, input };
  } catch (err) {
    return { error: `${err.name}: ${err.message}`, input };
  }
};

describe('buildEntityData equivalence with the ramda copy chains', () => {
  beforeAll(() => {
    vi.useFakeTimers({ toFake: ['Date'], now: new Date('2024-05-01T10:00:00.000Z') });
  });
  afterAll(() => {
    vi.useRealTimers();
  });
  beforeEach(() => {
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(STATUSES);
    vi.spyOn(cacheModule, 'getEntitiesMapFromCache').mockResolvedValue(new Map(MARKINGS.map((m) => [m.id, m])));
  });

  const cases = buildCases();
  it.each(USERS)('should build the same element and relations for every input, %s', async (_label, user, context) => {
    let built = 0;
    for (let index = 0; index < cases.length; index += 1) {
      const [name, type, factory, opts] = cases[index];
      const actual = await run(buildEntityData, context, user, factory, type, opts);
      const expected = await run(buildEntityDataReference, context, user, factory, type, opts);
      expect(actual.error, name).toBe(expected.error);
      expect(actual.result, name).toStrictEqual(expected.result);
      expect(JSON.stringify(actual.result), name).toBe(JSON.stringify(expected.result));
      if (actual.result) {
        expect(Object.keys(actual.result.element), name).toStrictEqual(Object.keys(expected.result.element));
        expect(Object.getPrototypeOf(actual.result.element), name).toBe(Object.getPrototypeOf(expected.result.element));
        actual.result.relations.forEach((relation, relationIndex) => {
          const expectedFrom = expected.result.relations[relationIndex].from;
          expect(Object.keys(relation.from), name).toStrictEqual(Object.keys(expectedFrom));
          expect(JSON.stringify(relation), name).toBe(JSON.stringify(expected.result.relations[relationIndex]));
        });
      }
      // Same side effects on the input (x_opencti_stix_ids is pushed into)
      expect(JSON.stringify(actual.input), name).toBe(JSON.stringify(expected.input));
      if (actual.result) built += 1;
    }
    expect(built).toBe(cases.length);
  });

  it('should keep the meta relationships pointing to the element without id, base_type and parent_types', async () => {
    const [, type, factory] = buildCases()[0];
    const { result, error } = await run(buildEntityData, { user_inside_platform_organization: true }, ADMIN_USER, factory, type, {});
    expect(error).toBeUndefined();
    expect(result.relations.length).toBeGreaterThan(0);
    result.relations.forEach((relation) => {
      expect(relation.from).not.toBe(result.element);
      expect(relation.from.id).toBeUndefined();
      expect(relation.from.base_type).toBeUndefined();
    });
  });
});
