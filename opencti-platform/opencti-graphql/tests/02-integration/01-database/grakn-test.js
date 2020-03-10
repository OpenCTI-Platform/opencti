import { head, includes, last, map } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import {
  attributeExists,
  dayFormat,
  escape,
  escapeString,
  executeRead,
  executeWrite,
  extractQueryVars,
  getGraknVersion,
  getSingleValueNumber,
  graknIsAlive,
  listEntities,
  listRelations,
  load,
  monthFormat,
  now,
  prepareDate,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  sinceNowInMinutes,
  utcDate,
  yearFormat
} from '../../../src/database/grakn';
import { INDEX_STIX_ENTITIES } from '../../../src/database/utils';

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
    expect(await countObjects('MigrationStatus')).toEqual(0);
    expect(await countObjects('MigrationReference')).toEqual(0);
    expect(await countObjects('Settings')).toEqual(1);
    expect(await countObjects('Tag')).toEqual(0);
    expect(await countObjects('Connector')).toEqual(0);
    expect(await countObjects('Group')).toEqual(0);
    expect(await countObjects('Workspace')).toEqual(0);
    expect(await countObjects('Token')).toEqual(1);
    expect(await countObjects('Stix-Domain')).toEqual(28);
    expect(await countObjects('Role')).toEqual(2);
    expect(await countObjects('Capability')).toEqual(19);
    expect(await countObjects('Stix-Observable')).toEqual(3);
    // Relations
  });
});

describe('Grakn entities listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false } = args;
  // const { parentType = null, search, filters } = args;
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
    expect(malware.alias.length).toEqual(1);
    expect(head(malware.alias)).toEqual('');
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
    let indicators = await listEntities(['Indicator'], ['name', 'alias'], { noCache });
    expect(indicators).not.toBeNull();
    expect(indicators.edges.length).toEqual(3);
    const options = { first: 1, after: offsetToCursor(1), orderBy: 'created', noCache: true };
    indicators = await listEntities(['Indicator'], ['name', 'alias'], options);
    expect(indicators.edges.length).toEqual(1);
    const indicator = head(indicators.edges).node;
    expect(indicator.name).toEqual('www.one-clap.jp');
  });
  it.each(noCacheCases)('should list entities with search (noCache = %s)', async noCache => {
    let options = { search: 'xolod', noCache };
    let indicators = await listEntities(['Indicator'], ['name'], options);
    expect(indicators.edges.length).toEqual(1);
    options = { search: 'location', noCache: true };
    indicators = await listEntities(['Indicator'], ['description'], options);
    expect(indicators.edges.length).toEqual(2);
    // Grakn is not a full text search engine :)
    options = { search: 'i want a location', noCache: true };
    indicators = await listEntities(['Indicator'], ['description'], options);
    expect(indicators.edges.length).toEqual(0);
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
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should list entities (noCache = %s)', async noCache => {
    const relations = await listRelations('stix_relation', undefined, { noCache }); // List all stix_relations
    expect(relations).not.toBeNull();
    expect(relations.edges.length).toEqual(11);
  });
});
