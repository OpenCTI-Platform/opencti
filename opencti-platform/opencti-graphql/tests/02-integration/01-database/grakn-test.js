import { head, includes, invertObj, last, map } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import {
  attributeExists,
  dayFormat,
  escape,
  escapeString,
  executeRead,
  executeWrite,
  extractQueryVars,
  find,
  getGraknVersion,
  getRelationInferredById,
  getSingleValueNumber,
  graknIsAlive,
  internalLoadEntityById,
  internalLoadEntityByStixId,
  listEntities,
  listRelations,
  load,
  loadByGraknId,
  monthFormat,
  now,
  prepareDate,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  REL_CONNECTED_SUFFIX,
  sinceNowInMinutes,
  utcDate,
  yearFormat
} from '../../../src/database/grakn';
import { INDEX_STIX_ENTITIES } from '../../../src/database/utils';
import { GATHERING_TARGETS_RULE, inferenceDisable, inferenceEnable } from '../../../src/domain/inference';
import { resolveNaturalRoles } from '../../../src/database/graknRoles';
import { REL_INDEX_PREFIX } from '../../../src/database/elasticSearch';

describe('Grakn basic and utils', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
    expect(getGraknVersion()).toEqual('1.6.2');
  });
  it('should escape according to grakn needs', () => {
    expect(escape({ key: 'json' })).toEqual({ key: 'json' });
    expect(escape('simple ident')).toEqual('simple ident');
    expect(escape('grakn\\special')).toEqual('grakn\\\\special');
    expect(escape('grakn;injection')).toEqual('grakn\\;injection');
    expect(escape('grakn,injection')).toEqual('grakn\\,injection');
    expect(escapeString('"\\test\\"')).toEqual('\\"\\\\test\\\\\\"');
  });
  it('should date utils correct', () => {
    expect(utcDate().isValid()).toBeTruthy();
    expect(utcDate(now()).isValid()).toBeTruthy();
    expect(sinceNowInMinutes(now())).toEqual(0);
    // Test with specific timezone
    expect(prepareDate('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31T23:00:00.001');
    expect(yearFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019');
    expect(monthFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12');
    expect(dayFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31');
    // Test with direct utc
    expect(prepareDate('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27T08:45:39.351');
    expect(yearFormat('2020-02-27T08:45:39.351Z')).toEqual('2020');
    expect(monthFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02');
    expect(dayFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27');
  });
});

describe('Grakn low level commands', () => {
  it('should read transaction handle correctly', async () => {
    const data = await executeRead(rTx => {
      return rTx.tx.query(`match $x sub report_class; get;`).then(it => it.collect());
    });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(1);
    const value = head(data).get('x');
    expect(value).not.toBeNull();
    expect(value.baseType).toEqual('ATTRIBUTE_TYPE');
  });
  it('should read transaction fail with bad query', async () => {
    const queryPromise = executeRead(rTx => {
      return rTx.tx.query(`match $x isa BAD_TYPE; get;`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should write transaction handle correctly', async () => {
    const connectorId = 'test-instance-connector';
    // Create a connector
    const creationData = await executeWrite(wTx => {
      return wTx.tx
        .query(`insert $c isa Connector, has internal_id_key "${connectorId}";`) //
        .then(it => it.collect());
    });
    expect(creationData).not.toBeNull();
    expect(creationData.length).toEqual(1);
    const value = head(creationData).get('c');
    expect(value).not.toBeNull();
    expect(value.id).not.toBeNull();
    expect(value.baseType).toEqual('ENTITY');
    // Delete it
    const deleteData = await executeWrite(wTx => {
      return wTx.tx
        .query(`match $c isa Connector, has internal_id_key "${connectorId}"; delete $c;`) //
        .then(it => it.collect());
    });
    expect(deleteData).not.toBeNull();
    expect(deleteData.length).toEqual(1);
    expect(head(deleteData).message()).toEqual('Delete successful.');
  });
  it('should write transaction fail with bad query', async () => {
    const queryPromise = executeWrite(rTx => {
      return rTx.tx.query(`insert $c isa Connector, has invalid_attr "invalid";`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should query vars fully extracted', async () => {
    let vars = extractQueryVars('match $x sub report_class; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(1);
    expect(head(vars).alias).toEqual('x');
    expect(head(vars).role).toBeUndefined();
    expect(head(vars).internalIdKey).toBeUndefined();
    // Extract vars with relation roles
    vars = extractQueryVars('match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    let aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('to').role).toEqual('gather');
    expect(aggregationMap.get('from').role).toEqual('part_of');
    // Extract var with internal_id specified
    vars = extractQueryVars(
      'match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering; $from has internal_id_key "ID"; get;'
    );
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').internalIdKey).toEqual('ID');
    // Extract right role reconstruct
    vars = extractQueryVars('match $to isa Sector; ($from, gather:$to) isa gathering; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part_of');
    expect(aggregationMap.get('to').role).toEqual('gather');
    // Extract left role reconstruct
    vars = extractQueryVars('match $to isa Sector; (part_of:$from, $to) isa gathering; get;');
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part_of');
    expect(aggregationMap.get('to').role).toEqual('gather');
  });
  it('should query vars check inconsistency', async () => {
    // Query must have a from and a to
    let query = 'match $to isa Sector; $rel(part_of:$part, $to) isa gathering; get;';
    expect(() => extractQueryVars(query)).toThrowError();
    // Relation is not found
    query = 'match $to isa Sector; $rel(part_of:$from, $to) isa undefined; get;';
    expect(() => extractQueryVars(query)).toThrowError();
    // Relation is found, one role is ok, the other is missing
    query = 'match $to isa Sector; $rel($to, source:$from) isa role_test_missing; get;';
    expect(() => extractQueryVars(query)).toThrowError();
    // Relation is found but the role specified is not in the map
    query = 'match $to isa Sector; $rel(sourced:$to, $from) isa role_test_missing; get;';
    expect(() => extractQueryVars(query)).toThrowError();
  });
});

describe('Grakn loaders', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should load simple query (noCache = %s)', async noCache => {
    const query = 'match $m isa Malware; $m has stix_id_key "malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88"; get;';
    const malware = await load(query, ['m'], { noCache });
    expect(malware.m).not.toBeNull();
    expect(malware.m.stix_id_key).toEqual('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
  });
  it('should load attributes values', async () => {
    const attrValues = await queryAttributeValues('report_class');
    expect(attrValues).not.toBeNull();
    expect(attrValues.edges.length).toEqual(2);
    const valueDefinitions = map(e => e.node.value, attrValues.edges);
    expect(includes('Threat Report', valueDefinitions)).toBeTruthy();
    expect(includes('Internal Report', valueDefinitions)).toBeTruthy();
  });
  it('should check attributes exist', async () => {
    const reportClassExist = await attributeExists('report_class');
    expect(reportClassExist).toBeTruthy();
    const notExist = await attributeExists('not_an_attribute');
    expect(notExist).not.toBeTruthy();
  });
  it('should check attributes resolve by id', async () => {
    const attrValues = await queryAttributeValues('report_class');
    const aggregationMap = new Map(attrValues.edges.map(i => [i.node.value, i.node]));
    const attributeId = aggregationMap.get('Threat Report').id;
    const attrValue = await queryAttributeValueByGraknId(attributeId);
    expect(attrValue).not.toBeNull();
    expect(attrValue.id).toEqual(attributeId);
    expect(attrValue.type).toEqual('report_class');
    expect(attrValue.value).toEqual('Threat Report');
  });
  it('should count accurate', async () => {
    const countObjects = type => getSingleValueNumber(`match $c isa ${type}; get; count;`);
    // Entities
    expect(await countObjects('Settings')).toEqual(1);
    expect(await countObjects('Tag')).toEqual(0);
    expect(await countObjects('Connector')).toEqual(0);
    expect(await countObjects('Group')).toEqual(0);
    expect(await countObjects('Workspace')).toEqual(0);
    expect(await countObjects('Token')).toEqual(1);
    expect(await countObjects('Marking-Definition')).toEqual(6);
    expect(await countObjects('Stix-Domain')).toEqual(35);
    expect(await countObjects('Role')).toEqual(2);
    expect(await countObjects('Capability')).toEqual(19);
    expect(await countObjects('Stix-Observable')).toEqual(4);
    // Relations
  });
});

describe('Grakn entities listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false }
  // const { parentType = null, search, filters }
  // filters part. Definition -> { key, values, fromRole, toRole }
  // TODO parentType is only use for elastic, that strange
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should list entities (noCache = %s)', async noCache => {
    const malwares = await listEntities(['Malware'], ['name', 'alias'], { noCache });
    expect(malwares).not.toBeNull();
    expect(malwares.edges.length).toEqual(2);
    const dataMap = new Map(malwares.edges.map(i => [i.node.stix_id_key, i.node]));
    const malware = dataMap.get('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware.grakn_id).not.toBeNull();
    expect(malware.id).toEqual('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    expect(malware.internal_id_key).toEqual('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    expect(malware.created_at_month).not.toBeNull();
    expect(malware.parent_types.length).toEqual(3);
    expect(includes('Malware', malware.parent_types)).toBeTruthy();
    expect(includes('Stix-Domain-Entity', malware.parent_types)).toBeTruthy();
    expect(includes('Stix-Domain', malware.parent_types)).toBeTruthy();
    expect(malware.created).toEqual('2019-09-30T16:38:26.000Z');
    expect(malware.name).toEqual('Paradise Ransomware');
    expect(malware.alias.length).toEqual(0);
    // eslint-disable-next-line
    expect(malware._index).toEqual(INDEX_STIX_ENTITIES);
  });
  it.each(noCacheCases)('should list multiple entities (noCache = %s)', async noCache => {
    const entities = await listEntities(['Malware', 'Organization'], ['name'], { noCache });
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(7); // 2 malwares + 5 organizations
    const aggregationMap = new Map(entities.edges.map(i => [i.node.name, i.node]));
    expect(aggregationMap.get('Paradise Ransomware')).not.toBeUndefined();
    expect(aggregationMap.get('Allied Universal')).not.toBeUndefined();
    expect(aggregationMap.get('ANSSI')).not.toBeUndefined();
    expect(aggregationMap.get('France')).toBeUndefined(); // Stix organization convert to Country with OpenCTI
  });
  it.each(noCacheCases)('should list entities with basic filtering (noCache = %s)', async noCache => {
    const options = { first: 1, after: offsetToCursor(2), orderBy: 'created', orderMode: 'desc', noCache };
    const indicators = await listEntities(['Indicator'], ['name', 'alias'], options);
    expect(indicators.edges.length).toEqual(1);
    const indicator = head(indicators.edges).node;
    expect(indicator.name).toEqual('2a0169c72c84e6d3fa49af701fd46ee7aaf1d1d9e107798d93a6ca8df5d25957');
  });
  it.each(noCacheCases)('should list entities with search (noCache = %s)', async noCache => {
    let options = { search: 'xolod', noCache };
    let indicators = await listEntities(['Indicator'], ['name'], options);
    expect(indicators.edges.length).toEqual(1);
    options = { search: 'location', noCache };
    indicators = await listEntities(['Indicator'], ['description'], options);
    expect(indicators.edges.length).toEqual(2);
    options = { search: 'i want a location', noCache };
    indicators = await listEntities(['Indicator'], ['description'], options);
    expect(indicators.edges.length).toEqual(noCache ? 0 : 3); // Grakn is not a full text search engine :)
  });
  it.each(noCacheCases)('should list entities order by relation (noCache = %s)', async noCache => {
    // France (f2ea7d37-996d-4313-8f73-42a8782d39a0) < localization > Hietzing (d1881166-f431-4335-bfed-b1c647e59f89)
    // Hietzing (d1881166-f431-4335-bfed-b1c647e59f89) < localization > France (f2ea7d37-996d-4313-8f73-42a8782d39a0)
    let options = { orderBy: 'localization.name', orderMode: 'desc', noCache };
    let identities = await listEntities(['Identity'], ['name'], options);
    expect(identities.edges.length).toEqual(2);
    expect(head(identities.edges).node.name).toEqual('France');
    expect(last(identities.edges).node.name).toEqual('Hietzing');
    options = { orderBy: 'localization.name', orderMode: 'asc', noCache };
    identities = await listEntities(['Identity'], ['name'], options);
    expect(identities.edges.length).toEqual(2);
    expect(head(identities.edges).node.name).toEqual('Hietzing');
    expect(last(identities.edges).node.name).toEqual('France');
  });
  it.each(noCacheCases)('should list entities order by relation id (noCache = %s)', async noCache => {
    // France (f2ea7d37-996d-4313-8f73-42a8782d39a0) < localization > Hietzing (d1881166-f431-4335-bfed-b1c647e59f89)
    // Hietzing (d1881166-f431-4335-bfed-b1c647e59f89) < localization > France (f2ea7d37-996d-4313-8f73-42a8782d39a0)
    const options = { orderBy: 'rel_localization.internal_id_key', orderMode: 'desc', noCache };
    const identities = await listEntities(['Identity'], ['name'], options);
    expect(identities.edges.length).toEqual(2);
    expect(head(identities.edges).node.name).toEqual('Hietzing');
    expect(last(identities.edges).node.name).toEqual('France');
  });
  it.each(noCacheCases)('should list entities with attribute filters (noCache = %s)', async noCache => {
    const filters = [
      { key: 'external_id', values: ['T1369'] },
      { key: 'name', values: ['Spear phishing messages with malicious links'] }
    ];
    const options = { filters, noCache };
    const attacks = await listEntities(['Attack-Pattern'], ['name'], options);
    expect(attacks).not.toBeNull();
    expect(attacks.edges.length).toEqual(1);
    expect(head(attacks.edges).node.id).toEqual('9f7f00f9-304b-4055-8c4f-f5eadb00de3b');
    expect(head(attacks.edges).node.stix_id_key).toEqual('attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc');
  });
  it.each(noCacheCases)('should list multiple entities with attribute filters (noCache = %s)', async noCache => {
    const filters = [{ key: `rel_created_by_ref.internal_id_key`, values: ['91649a10-216b-4f79-a2fe-e6549e1b6893'] }];
    const options = { filters, noCache };
    const entities = await listEntities(['Attack-Pattern', 'Intrusion-Set'], ['name'], options);
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(3);
  });
  const relationFilterUseCases = [
    ['name', 'The MITRE Corporation', true],
    ['name', 'The MITRE Corporation', false],
    ['internal_id_key', '91649a10-216b-4f79-a2fe-e6549e1b6893', true],
    ['internal_id_key', '91649a10-216b-4f79-a2fe-e6549e1b6893', false]
  ];
  it.each(relationFilterUseCases)(
    'should list entities with ref relation %s=%s filters (noCache = %s)',
    async (field, val, noCache) => {
      const filters = [{ key: `rel_created_by_ref.${field}`, values: [val] }];
      const options = { filters, noCache };
      const entities = await listEntities(['Stix-Domain-Entity'], ['name'], options);
      expect(entities).not.toBeNull();
      expect(entities.edges.length).toEqual(3);
      const aggregationMap = new Map(entities.edges.map(i => [i.node.stix_id_key, i.node]));
      expect(aggregationMap.get('attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17')).not.toBeUndefined();
      expect(aggregationMap.get('attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc')).not.toBeUndefined();
      expect(aggregationMap.get('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7')).not.toBeUndefined();
    }
  );
});

describe('Grakn relations listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false, inferred = false, forceNatural = false }
  // const { filters = [], search, fromRole, fromId, toRole, toId, fromTypes = [], toTypes = [] }
  // const { firstSeenStart, firstSeenStop, lastSeenStart, lastSeenStop, weights = [] }
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should find entities in grakn (noCache = %s)', async noCache => {
    const data = await find('match $m isa Malware; get;', ['m'], { noCache });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map(i => [i.m.stix_id_key, i.m]));
    const malware = aggregationMap.get('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).not.toBeUndefined();
    expect(malware.name).toEqual('Paradise Ransomware');
  });
  // uses: { user: ROLE_FROM, usage: ROLE_TO }
  const checkRoles = (relations, from, to) => {
    // Roles with be set according to query specification
    for (let index = 0; index < relations.length; index += 1) {
      const { fromRole, toRole } = relations[index];
      expect(fromRole).toEqual(from);
      expect(toRole).toEqual(to);
    }
  };
  it.each(noCacheCases)('should find relations no roles in grakn (noCache = %s)', async noCache => {
    // Getting everything if only relations lead to default roles ordering
    const relations = await find('match $rel isa uses; get;', ['rel'], { noCache });
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(relations.map(r => r.rel), 'user', 'usage'); // Roles with be set according to query specification
  });
  it.each(noCacheCases)('should find relations inverse roles in grakn (noCache = %s)', async noCache => {
    // Getting everything specifying all roles respect the roles of the query
    const relations = await find('match $rel(usage:$from, user:$to) isa uses; get;', ['rel'], { noCache });
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(relations.map(r => r.rel), 'usage', 'user');
  });
  it.each(noCacheCases)('should find relations partial right roles in grakn (noCache = %s)', async noCache => {
    // Getting everything with partial roles respect the roles of the query
    const relations = await find('match $rel($from, user:$to) isa uses; get;', ['rel'], { noCache });
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(relations.map(r => r.rel), 'usage', 'user');
  });
  it.each(noCacheCases)('should find relations partial left roles in grakn (noCache = %s)', async noCache => {
    // Getting everything with partial roles respect the roles of the query
    const relations = await find('match $rel(usage:$from, $to) isa uses; get;', ['rel'], { noCache });
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(relations.map(r => r.rel), 'usage', 'user');
  });
  it.each(noCacheCases)('should list relations (noCache = %s)', async noCache => {
    const stixRelations = await listRelations('stix_relation', { noCache });
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(15);
    const embeddedRelations = await listRelations('stix_relation_embedded', { noCache });
    expect(embeddedRelations).not.toBeNull();
    expect(embeddedRelations.edges.length).toEqual(76);
  });
  it.each(noCacheCases)('should list relations with no id (noCache = %s)', noCache => {
    expect(listRelations('uses', { noCache, fromTypes: ['Attack-Pattern'] })).rejects.toThrow();
    expect(listRelations('uses', { noCache, toTypes: ['Attack-Pattern'] })).rejects.toThrow();
    expect(listRelations('uses', { noCache, search: 'to description' })).rejects.toThrow();
  });
  it.each(noCacheCases)('should list relations with id option (noCache = %s)', async noCache => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330' };
    const thing = await internalLoadEntityById('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    const stixRelations = await listRelations('uses', options);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(thing.grakn_id);
    }
  });
  it.each(noCacheCases)('should list relations with from types option (noCache = %s)', async noCache => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const intrusionSet = await internalLoadEntityByStixId('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    expect(intrusionSet.entity_type).toEqual('intrusion-set');
    const options = { noCache, fromId: '82316ffd-a0ec-4519-a454-6566f8f5676c', fromTypes: ['Intrusion-Set'] };
    const stixRelations = await listRelations('targets', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(intrusionSet.grakn_id);
    }
  });
  it.each(noCacheCases)('should list relations with to types option (noCache = %s)', async noCache => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const malware = await internalLoadEntityByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330', toTypes: ['Attack-Pattern'] };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line no-await-in-loop
      const toThing = await loadByGraknId(stixRelation.toId);
      expect(toThing.entity_type).toEqual('attack-pattern');
      expect(stixRelation.fromId).toEqual(malware.grakn_id);
    }
  });
  it.each(noCacheCases)('should list relations with first and order filtering (noCache = %s)', async noCache => {
    const options = { first: 6, after: offsetToCursor(0), orderBy: 'created', orderMode: 'desc', noCache };
    const stixRelations = await listRelations('stix_relation', options);
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(6);
    // Every relations must have natural ordering for from and to
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line camelcase
      const { fromRole, toRole, relationship_type } = stixRelation;
      const roles = invertObj(resolveNaturalRoles(relationship_type));
      expect(fromRole).toEqual(roles.from);
      expect(toRole).toEqual(roles.to);
    }
    const relation = head(stixRelations.edges).node;
    expect(relation.created).toEqual('2020-03-25T14:10:20.065Z');
    const from = await loadByGraknId(relation.fromId);
    expect(from.stix_id_key).toEqual('incident--0b626d41-1d8d-4b96-86fa-ad49cea2cfd4');
    const to = await loadByGraknId(relation.toId);
    expect(to.stix_id_key).toEqual('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
  });
  it.each(noCacheCases)('should list relations ordered by relation (noCache = %s)', async noCache => {
    // "relationship_type": "uses",
    // "id": "relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02" > 209cbdf0-fc5e-47c9-8023-dd724993ae55
    //  "relationship_type": "indicates",
    //  "source_ref": "indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf", > 1c47970a-a23b-4b6c-85cd-ab73ddb506c6 [2a0169c72c84e6d3fa49af701fd46ee7aaf1d1d9e107798d93a6ca8df5d25957]
    //  "target_ref": "relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02",

    // "relationship_type": "uses",
    // "id": "relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de" > 50a205fa-92ec-4ec9-bf62-e065dd85f5d4
    //  "relationship_type": "indicates",
    //  "source_ref": "indicator--51640662-9c78-4402-932f-1d4531624723" > c8739116-e1d9-4c4f-b091-590147b3d7b9 [www.one-clap.jp]
    //  "target_ref": "relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de",
    //  "relationship_type": "indicates",
    //  "source_ref": "indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079" > e7652cb6-777a-4220-9b64-0543ef36d467 [www.xolod-teplo.ru]
    //  "target_ref": "relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de",

    // "relationship_type": "uses",
    // "id": "relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3",
    // No relation on it

    const options = { orderBy: 'rel_indicates.internal_id_key', orderMode: 'asc', noCache };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const first = head(stixRelations.edges).node;
    const second = last(stixRelations.edges).node;
    expect(first.stix_id_key).toEqual('relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02');
    expect(second.stix_id_key).toEqual('relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de');
  });
  it.each(noCacheCases)('should list relations with relation filtering (noCache = %s)', async noCache => {
    let stixRelations = await listRelations('uses', { noCache });
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(3);
    // Filter the list through relation filter
    // [Malware: Paradise Ransomware] ---- (user) ---- <uses> ---- (usage) ---- [Attack pattern: Spear phishing messages with text only]
    //                                                   |
    //                                             (characterize)
    //                                                   |
    //                                              < indicates >
    //                                                   |
    //                                               (indicator)
    //                                                   |
    //                                     [Indicator: www.xolod-teplo.ru]
    const indicatorId = 'e7652cb6-777a-4220-9b64-0543ef36d467'; // indicator -> www.xolod-teplo.ru
    const relationFilter = { relation: 'indicates', fromRole: 'characterize', toRole: 'indicator', id: indicatorId };
    const options = { noCache, relationFilter };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = head(stixRelations.edges).node;
    expect(relation.stix_id_key).toEqual('relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de');
    expect(relation.fromRole).toEqual('user');
    expect(relation.toRole).toEqual('usage');
    expect(relation.created).toEqual('2020-03-01T14:05:16.797Z');
  });
  it.each(noCacheCases)('should list relations with relation filtering on report (noCache = %s)', async noCache => {
    const relationFilter = {
      relation: 'object_refs',
      fromRole: 'so',
      toRole: 'knowledge_aggregation',
      id: '685aac19-d2f6-4835-a256-0631bb322732'
    };
    const args = { noCache, relationFilter };
    const stixRelations = await listRelations('stix_relation', args);
    expect(stixRelations.edges.length).toEqual(11);
  });
  it.each(noCacheCases)('should list relations with to attribute filtering (noCache = %s)', async noCache => {
    const options = { orderBy: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`, orderMode: 'asc', noCache };
    const stixRelations = await listRelations('uses', options);
    // TODO Fix that test
    expect(stixRelations).not.toBeNull();
  });
  it.each(noCacheCases)('should list relations with forceNatural (noCache = %s)', async noCache => {
    // uses: { user: ROLE_FROM, usage: ROLE_TO }
    // Here we force the direction with the fromId option
    // However the forNatural will force the natural order.
    const options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330', forceNatural: true };
    const stixRelations = await listRelations('uses', options);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromRole).toEqual('user');
      expect(stixRelation.toRole).toEqual('usage');
    }
    // Check the specific relation that have been reversed
    const thing = await internalLoadEntityById('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    const aggregationMap = new Map(stixRelations.edges.map(i => [i.node.stix_id_key, i]));
    const reversedRelation = aggregationMap.get('relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3');
    expect(reversedRelation.fromId).not.toEqual(thing.grakn_id);
  });
  it.each(noCacheCases)('should list relations with search (noCache = %s)', async noCache => {
    const options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330', search: 'Spear phishing' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const relTargets = await Promise.all(map(s => loadByGraknId(s.node.toId), stixRelations.edges));
    for (let index = 0; index < relTargets.length; index += 1) {
      const target = relTargets[index];
      expect(target.name).toEqual(expect.stringContaining('Spear phishing'));
    }
  });
  it.each(noCacheCases)('should list relations first seen (noCache = %s)', async noCache => {
    // Uses relations first seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-28T23:00:00.000Z"
    const options = { noCache, firstSeenStart: '2020-02-29T22:00:00.000Z', firstSeenStop: '2020-02-29T23:30:00.000Z' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
  });
  it.each(noCacheCases)('should list relations last seen (noCache = %s)', async noCache => {
    // Uses relations last seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-29T23:00:00.000Z"
    let options = { noCache, lastSeenStart: '2020-02-29T23:00:00.000Z', lastSeenStop: '2020-02-29T23:00:00.000Z' };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
    options = { noCache, lastSeenStart: '2020-02-29T22:59:59.000Z', lastSeenStop: '2020-02-29T23:00:01.000Z' };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(3);
  });
  it.each(noCacheCases)('should list relations with weight (noCache = %s)', async noCache => {
    const options = { noCache, weights: [4] };
    const stixRelations = await listRelations('indicates', options);
    expect(stixRelations.edges.length).toEqual(1);
  });
  it.each(noCacheCases)('should list relations with filters (noCache = %s)', async noCache => {
    const key = `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`;
    let filters = [{ key, operator: 'match', values: ['malicious'] }];
    // malware--faa5b705-cf44-4e50-8472-29e5fec43c3c - Paradise Ransomware
    let options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330', filters };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = head(stixRelations.edges).node;
    const target = await loadByGraknId(relation.toId);
    expect(target.name).toEqual(expect.stringContaining('malicious'));
    // Test with exact match
    filters = [{ key, values: ['malicious'] }];
    options = { noCache, fromId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330', filters };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
  });
});

describe('Grakn relations with inferences', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should inference explanation correctly resolved', async noCache => {
    await inferenceEnable(GATHERING_TARGETS_RULE);
    // Find the Grakn ID of the connections to build the inferred relation
    // In the data loaded its APT41 (intrusion-set) < target > Southwire (organization)
    const apt28 = await internalLoadEntityByStixId('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const southwire = await internalLoadEntityByStixId('organization--5a510e41-5cb2-45cc-a191-a4844ea0a141');
    // Build the inferred relation for testing
    const inference = `{ $rel(source: $from, target: $to) isa targets; $from id ${apt28.grakn_id}; $to id ${southwire.grakn_id}; };`;
    const inferenceId = Buffer.from(inference).toString('base64');
    const relation = await getRelationInferredById(inferenceId, { noCache });
    expect(relation).not.toBeNull();
    expect(relation.relationship_type).toEqual('targets');
    expect(relation.inferred).toBeTruthy();
    expect(relation.fromRole).toEqual('source');
    expect(relation.toRole).toEqual('target');
    expect(relation.inferences).not.toBeNull();
    expect(relation.inferences.edges.length).toEqual(2);
    const aggregationMap = new Map(relation.inferences.edges.map(i => [i.node.stix_id_key, i.node]));
    // relationship--3541149d-1af6-4688-993c-dc32c7ee3880
    // APT41 > intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
    // Allied Universal > organization--c017f212-546b-4f21-999d-97d3dc558f7b
    const firstSegment = aggregationMap.get('relationship--3541149d-1af6-4688-993c-dc32c7ee3880');
    expect(firstSegment).not.toBeUndefined();
    expect(firstSegment.internal_id_key).toEqual('36d591b6-54b9-4152-ab89-79c7dad709f7');
    expect(firstSegment.fromRole).toEqual('source');
    expect(firstSegment.toRole).toEqual('target');
    // relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7
    // Allied Universal > organization--c017f212-546b-4f21-999d-97d3dc558f7b
    // Southwire > organization--5a510e41-5cb2-45cc-a191-a4844ea0a141
    const secondSegment = aggregationMap.get('relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7');
    expect(secondSegment).not.toBeUndefined();
    expect(secondSegment.internal_id_key).toEqual('b7a4d86f-220e-412a-8135-6e9fb9f7b296');
    expect(secondSegment.fromRole).toEqual('part_of');
    expect(secondSegment.toRole).toEqual('gather');
    // Disable the rule
    await inferenceDisable(GATHERING_TARGETS_RULE);
  });
});
