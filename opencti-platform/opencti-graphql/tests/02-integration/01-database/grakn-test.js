import { assoc, head, includes, last, map } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import {
  attributeExists,
  dayFormat,
  distributionEntities,
  distributionEntitiesThroughRelations,
  distributionRelations,
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
  listEntities,
  listRelations,
  load,
  loadEntityById,
  loadRelationById,
  monthFormat,
  now,
  prepareDate,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  querySubTypes,
  REL_CONNECTED_SUFFIX,
  sinceNowInMinutes,
  timeSeriesEntities,
  timeSeriesRelations,
  updateAttribute,
  yearFormat,
} from '../../../src/database/grakn';
import { attributeUpdate, findAll as findAllAttributes } from '../../../src/domain/attribute';
import { INDEX_STIX_DOMAIN_OBJECTS, utcDate } from '../../../src/database/utils';
import { PART_OF_TARGETS_RULE, inferenceDisable, inferenceEnable } from '../../../src/domain/inference';
import { elLoadById, REL_INDEX_PREFIX, elLoadByStixId } from '../../../src/database/elasticSearch';
import { ADMIN_USER } from '../../utils/testQuery';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  RELATION_MITIGATES,
} from '../../../src/utils/idGenerator';

describe('Grakn basic and utils', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
    expect(getGraknVersion()).toEqual('1.7.2');
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
    const data = await executeRead((rTx) => {
      return rTx.query(`match $x sub report_types; get;`).then((it) => it.collect());
    });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(1);
    const value = head(data).get('x');
    expect(value).not.toBeNull();
    expect(value.baseType).toEqual('ATTRIBUTE_TYPE');
  });
  it('should read transaction fail with bad query', async () => {
    const queryPromise = executeRead((rTx) => {
      return rTx.query(`match $x isa BAD_TYPE; get;`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should write transaction handle correctly', async () => {
    const connectorId = 'test-instance-connector';
    // Create a connector
    const creationData = await executeWrite((wTx) => {
      return wTx
        .query(`insert $c isa Connector, has internal_id "${connectorId}", has standard_id "${connectorId}";`) //
        .then((it) => it.collect());
    });
    expect(creationData).not.toBeNull();
    expect(creationData.length).toEqual(1);
    const value = head(creationData).get('c');
    expect(value).not.toBeNull();
    expect(value.id).not.toBeNull();
    expect(value.baseType).toEqual('ENTITY');
    // Delete it
    const deleteData = await executeWrite((wTx) => {
      return wTx
        .query(`match $c isa Connector, has internal_id "${connectorId}"; delete $c;`) //
        .then((it) => it.collect());
    });
    expect(deleteData).not.toBeNull();
    expect(deleteData.length).toEqual(1);
    expect(head(deleteData).message()).toEqual('Delete successful.');
  });
  it('should write transaction fail with bad query', async () => {
    const queryPromise = executeWrite((rTx) => {
      return rTx.query(`insert $c isa Connector, has invalid_attr "invalid";`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should query vars fully extracted', async () => {
    let vars = extractQueryVars('match $x sub report_types; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(1);
    expect(head(vars).alias).toEqual('x');
    expect(head(vars).role).toBeUndefined();
    expect(head(vars).internalIdKey).toBeUndefined();
    // Extract vars with relation roles
    vars = extractQueryVars('match $to isa Sector; $rel(xxxx:$from, yyyy:$to) isa part-of; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    let aggregationMap = new Map(vars.map((i) => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('xxxx');
    expect(aggregationMap.get('to').role).toEqual('yyyy');
    // Extract var with internal_id specified
    vars = extractQueryVars(
      'match $to isa Sector; $rel(part-of_from:$from, part-of_to:$to) isa part-of; $from has internal_id "ID"; get;'
    );
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    aggregationMap = new Map(vars.map((i) => [i.alias, i]));
    expect(aggregationMap.get('from').internalIdKey).toEqual('ID');
    // Extract right role reconstruct
    vars = extractQueryVars('match $to isa Sector; ($from, part-of_to:$to) isa part-of; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map((i) => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part-of_from');
    expect(aggregationMap.get('to').role).toEqual('part-of_to');
    // Extract left role reconstruct
    vars = extractQueryVars('match $to isa Sector; (part-of_from:$from, $to) isa part-of; get;');
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map((i) => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part-of_from');
    expect(aggregationMap.get('to').role).toEqual('part-of_to');
  });
  it('should throw exception when IDs are not requested', async () => {
    // rel_id not found
    let query =
      'match $rel($from, $to) isa Basic-Relation; $from has internal_id $rel_from_id; $to has internal_id $rel_to_id; get;';
    expect(find(query, ['rel'])).rejects.toThrow();
    // from_id not found
    query = 'match $rel($from, $to) isa Basic-Relation; get;';
    expect(find(query, ['from'])).rejects.toThrow();
    // to_id not found
    query = 'match $rel($from, $to) isa Basic-Relation; get;';
    expect(find(query, ['to'])).rejects.toThrow();
  });
});

describe('Grakn loaders', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should load simple query (noCache = %s)', async (noCache) => {
    const query =
      'match $m isa Malware; $m has stix_ids "malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88", has internal_id $m_id; get;';
    const malware = await load(query, ['m'], { noCache });
    expect(malware.m).not.toBeNull();
    expect(malware.m.stix_ids).toEqual(['malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88']);
    expect(malware.m.standard_id).toEqual('malware--a62f1fb7-ea66-570e-a007-ea50efce1606');
  });
  it('should load subTypes values', async () => {
    const stixObservableSubTypes = await querySubTypes('Stix-Cyber-Observable');
    expect(stixObservableSubTypes).not.toBeNull();
    expect(stixObservableSubTypes.edges.length).toEqual(27);
    const subTypeLabels = map((e) => e.node.label, stixObservableSubTypes.edges);
    expect(includes('IPv4-Addr', subTypeLabels)).toBeTruthy();
    expect(includes('IPv6-Addr', subTypeLabels)).toBeTruthy();
  });
  it('should load attributes values', async () => {
    const attrValues = await queryAttributeValues('report_types');
    expect(attrValues).not.toBeNull();
    expect(attrValues.edges.length).toEqual(2);
    const valueDefinitions = map((e) => e.node.value, attrValues.edges);
    expect(includes('threat-report', valueDefinitions)).toBeTruthy();
    expect(includes('internal-report', valueDefinitions)).toBeTruthy();
  });
  it('should check attributes exist', async () => {
    const reportClassExist = await attributeExists('report_types');
    expect(reportClassExist).toBeTruthy();
    const notExist = await attributeExists('not_an_attribute');
    expect(notExist).not.toBeTruthy();
  });
  it('should check attributes resolve by id', async () => {
    const attrValues = await queryAttributeValues('report_types');
    const aggregationMap = new Map(attrValues.edges.map((i) => [i.node.value, i.node]));
    const attributeId = aggregationMap.get('threat-report').id;
    const attrValue = await queryAttributeValueByGraknId(attributeId);
    expect(attrValue).not.toBeNull();
    expect(attrValue.id).toEqual(attributeId);
    expect(attrValue.type).toEqual('report_types');
    expect(attrValue.value).toEqual('threat-report');
  });
  it('should count accurate', async () => {
    const countObjects = (type) => getSingleValueNumber(`match $c isa ${type}; get; count;`);
    // Entities
    expect(await countObjects('Settings')).toEqual(1);
    expect(await countObjects('Label')).toEqual(13);
    expect(await countObjects('Connector')).toEqual(0);
    expect(await countObjects('Group')).toEqual(0);
    expect(await countObjects('Workspace')).toEqual(0);
    expect(await countObjects('Token')).toEqual(1);
    expect(await countObjects('Marking-Definition')).toEqual(6);
    expect(await countObjects('Stix-Domain-Object')).toEqual(36);
    expect(await countObjects('Role')).toEqual(2);
    expect(await countObjects('Capability')).toEqual(19);
    expect(await countObjects('Stix-Cyber-Observable')).toEqual(4);
    // Relations
  });
});

describe('Grakn attribute updater', () => {
  const noCacheCases = [[true], [false]];
  it('should update fail for read only attributes', async () => {
    const campaign = await elLoadByStixId('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const input = { key: 'observable_value', value: ['test'] };
    const update = executeWrite((wTx) => {
      return updateAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, input, wTx);
    });
    expect(update).rejects.toThrow();
  });
  it('should update dont do anything if already the same', async () => {
    const campaign = await elLoadByStixId('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const input = { key: 'description', value: ['A test campaign'] };
    const update = await executeWrite((wTx) => {
      return updateAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, input, wTx);
    });
    expect(update).toEqual(campaignId);
  });
  it.each(noCacheCases)('should update date with dependencies', async (noCache) => {
    const stixId = 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214';
    let campaign = await internalLoadEntityById(stixId, { noCache });
    const campaignId = campaign.internal_id;
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    const type = 'Stix-Domain-Object';
    let input = { key: 'first_seen', value: ['2020-02-20T08:45:43.366Z'] };
    let update = await executeWrite((wTx) => updateAttribute(ADMIN_USER, campaignId, type, input, wTx));
    expect(update).toEqual(campaignId);
    campaign = await internalLoadEntityById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-20T08:45:43.366Z');
    expect(campaign.first_seen_day).toEqual('2020-02-20');
    expect(campaign.first_seen_month).toEqual('2020-02');
    expect(campaign.first_seen_year).toEqual('2020');
    // Value back to before
    input = { key: 'first_seen', value: ['2020-02-27T08:45:43.365Z'] };
    update = await executeWrite((wTx) => updateAttribute(ADMIN_USER, campaignId, type, input, wTx));
    expect(update).toEqual(campaignId);
    campaign = await internalLoadEntityById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    expect(campaign.first_seen_day).toEqual('2020-02-27');
  });
  it.each(noCacheCases)('should update numeric', async (noCache) => {
    const stixId = 'relationship--efc9bbb8-e606-4fb1-83ae-d74690fd0416';
    let relation = await loadRelationById(stixId, 'stix-core-relationship', { noCache });
    const relationId = relation.internal_id;
    expect(relation.confidence).toEqual(1);
    let input = { key: 'confidence', value: [5] };
    await executeWrite((wTx) => updateAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, input, wTx));
    relation = await loadRelationById(stixId, { noCache });
    expect(relation.confidence).toEqual(5);
    // Value back to before
    input = { key: 'confidence', value: [1] };
    await executeWrite((wTx) => updateAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, input, wTx));
    relation = await loadRelationById(stixId, { noCache });
    expect(relation.confidence).toEqual(1);
  });
  it.each(noCacheCases)('should update multivalued attribute', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const type = 'Stix-Domain-Object';
    let identity = await internalLoadEntityById(stixId, { noCache });
    const identityId = identity.internal_id;
    expect(identity.aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
    let input = { key: 'aliases', value: ['Computer', 'Test', 'Grakn'] };
    await executeWrite((wTx) => updateAttribute(ADMIN_USER, identityId, type, input, wTx));
    identity = await internalLoadEntityById(stixId, { noCache });
    expect(identity.aliases.sort()).toEqual(['Computer', 'Test', 'Grakn'].sort());
    // Value back to before
    input = { key: 'aliases', value: ['Computer Incident', 'Incident'] };
    await executeWrite((wTx) => updateAttribute(ADMIN_USER, identityId, type, input, wTx));
    identity = await internalLoadEntityById(stixId, { noCache });
    expect(identity.aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
  });
});

describe('Grakn entities listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false }
  // filters part. Definition -> { key, values, fromRole, toRole }
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should list entities (noCache = %s)', async (noCache) => {
    const malwares = await listEntities(['Malware'], ['name', 'aliases'], { noCache });
    expect(malwares).not.toBeNull();
    expect(malwares.edges.length).toEqual(2);
    const dataMap = new Map(malwares.edges.map((i) => [head(i.node.stix_ids), i.node]));
    const malware = dataMap.get('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware.grakn_id).not.toBeNull();
    expect(malware.standard_id).toEqual('malware--2a2c2895-43c2-5df3-bf8a-530f5703f687');
    expect(malware.created_at_month).not.toBeNull();
    expect(malware.parent_types.length).toEqual(4);
    expect(includes('Stix-Domain-Object', malware.parent_types)).toBeTruthy();
    expect(includes('Stix-Core-Object', malware.parent_types)).toBeTruthy();
    expect(includes('Stix-Object', malware.parent_types)).toBeTruthy();
    expect(includes('Basic-Object', malware.parent_types)).toBeTruthy();
    expect(malware.created).toEqual('2019-09-30T16:38:26.000Z');
    expect(malware.name).toEqual('Paradise Ransomware');
    // eslint-disable-next-line
    expect(malware._index).toEqual(INDEX_STIX_DOMAIN_OBJECTS);
  });
  it.each(noCacheCases)('should list multiple entities (noCache = %s)', async (noCache) => {
    const entities = await listEntities(['Malware', 'Organization'], ['name'], { noCache });
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(10); // 2 malwares + 8 organizations
    const aggregationMap = new Map(entities.edges.map((i) => [i.node.name, i.node]));
    expect(aggregationMap.get('Paradise Ransomware')).not.toBeUndefined();
    expect(aggregationMap.get('Allied Universal')).not.toBeUndefined();
    expect(aggregationMap.get('ANSSI')).not.toBeUndefined();
    expect(aggregationMap.get('France')).toBeUndefined(); // Stix organization convert to Country with OpenCTI
  });
  it.each(noCacheCases)('should list entities with basic filtering (noCache = %s)', async (noCache) => {
    const options = { first: 1, after: offsetToCursor(2), orderBy: 'created', orderMode: 'desc', noCache };
    const indicators = await listEntities(['Indicator'], ['name', 'alias'], options);
    expect(indicators.edges.length).toEqual(1);
    const indicator = head(indicators.edges).node;
    expect(indicator.name).toEqual('2a0169c72c84e6d3fa49af701fd46ee7aaf1d1d9e107798d93a6ca8df5d25957');
  });
  it.each(noCacheCases)('should list entities with search (noCache = %s)', async (noCache) => {
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
  it.each(noCacheCases)('should list entities order by relation (noCache = %s)', async (noCache) => {
    // France (f2ea7d37-996d-4313-8f73-42a8782d39a0) < localization > Hietzing (d1881166-f431-4335-bfed-b1c647e59f89)
    // Hietzing (d1881166-f431-4335-bfed-b1c647e59f89) < localization > France (f2ea7d37-996d-4313-8f73-42a8782d39a0)
    let options = { orderBy: 'rel_located-at.name', orderMode: 'desc', noCache };
    let identities = await listEntities(['Location'], ['name'], options);
    expect(identities.edges.length).toEqual(6);
    const firstDescResult =
      head(identities.edges).node.name === 'Europe' || head(identities.edges).node.name === 'France';
    expect(firstDescResult).toBeTruthy();
    expect(last(identities.edges).node.name).toEqual('Western Europe');
    options = { orderBy: 'rel_located-at.name', orderMode: 'asc', noCache };
    identities = await listEntities(['Location'], ['name'], options);
    expect(identities.edges.length).toEqual(6);
    expect(head(identities.edges).node.name).toEqual('Western Europe');
    const lastAscResult =
      last(identities.edges).node.name === 'Europe' || last(identities.edges).node.name === 'France';
    expect(lastAscResult).toBeTruthy();
  });
  it.each(noCacheCases)('should list entities order by relation id (noCache = %s)', async (noCache) => {
    // France (f2ea7d37-996d-4313-8f73-42a8782d39a0) < localization > Hietzing (d1881166-f431-4335-bfed-b1c647e59f89)
    // Hietzing (d1881166-f431-4335-bfed-b1c647e59f89) < localization > France (f2ea7d37-996d-4313-8f73-42a8782d39a0)
    // We accept that ElasticSearch is not able to have both direction of the relations
    const options = { orderBy: 'rel_located-at.standard_id', orderMode: 'desc', noCache };
    const locations = await listEntities(['Location'], ['name'], options);
    expect(locations.edges.length).toEqual(6);
    const firstResults = ['France'];
    expect(includes(head(locations.edges).node.name, firstResults)).toBeTruthy();
    const lastResults = ['Western Europe'];
    expect(includes(last(locations.edges).node.name, lastResults)).toBeTruthy();
  });
  it.each(noCacheCases)('should list entities with attribute filters (noCache = %s)', async (noCache) => {
    const filters = [
      { key: 'x_mitre_id', values: ['T1369'] },
      { key: 'name', values: ['Spear phishing messages with malicious links'] },
    ];
    const options = { filters, noCache };
    const attacks = await listEntities(['Attack-Pattern'], ['name'], options);
    expect(attacks).not.toBeNull();
    expect(attacks.edges.length).toEqual(1);
    expect(head(attacks.edges).node.standard_id).toEqual('attack-pattern--c9b2ad0f-6808-5359-b680-21e7e32ff1a6');
    expect(head(attacks.edges).node.stix_ids).toEqual(['attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc']);
  });
  it.each(noCacheCases)('should list multiple entities with attribute filters (noCache = %s)', async (noCache) => {
    const identity = await elLoadByStixId('identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5');
    const filters = [{ key: `rel_created-by.internal_id`, values: [identity.internal_id] }];
    const options = { filters, noCache };
    const entities = await listEntities(['Attack-Pattern', 'Intrusion-Set'], ['name'], options);
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(3);
  });

  const relationFilterUseCases = [
    ['name', 'The MITRE Corporation', true],
    ['name', 'The MITRE Corporation', false],
    ['stix_ids', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', true],
    ['stix_ids', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', false],
  ];
  it.each(relationFilterUseCases)(
    'should list entities with ref relation %s=%s filters (noCache = %s)',
    async (field, val, noCache) => {
      const filters = [{ key: `rel_created-by.${field}`, values: [val], toRole: 'created-by_to' }];
      const options = { filters, noCache };
      const entities = await listEntities(['Stix-Domain-Object'], ['name'], options);
      expect(entities).not.toBeNull();
      expect(entities.edges.length).toEqual(5);
      const aggregationMap = new Map(entities.edges.map((i) => [head(i.node.stix_ids || ['fake']), i.node]));
      expect(aggregationMap.get('attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17')).not.toBeUndefined();
      expect(aggregationMap.get('attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc')).not.toBeUndefined();
      expect(aggregationMap.get('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7')).not.toBeUndefined();
    }
  );
});

describe('Grakn relations listing', () => {
  // const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false, inferred = false, forceNatural = false }
  // const { filters = [], search, fromRole, fromId, toRole, toId, fromTypes = [], toTypes = [] }
  // const { firstSeenStart, firstSeenStop, lastSeenStart, lastSeenStop, confidences = [] }
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should find entities in grakn (noCache = %s)', async (noCache) => {
    const data = await find('match $m isa Malware, has internal_id $m_id; get;', ['m'], { noCache });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map((i) => [head(i.m.stix_ids), i.m]));
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
  it.each(noCacheCases)('should find relations no roles in grakn (noCache = %s)', async (noCache) => {
    // Getting everything if only relations lead to default roles ordering
    const relations = await find(
      'match $rel($from, $to) isa uses, has internal_id $rel_id; ' +
        '$from has internal_id $rel_from_id; ' +
        '$to has internal_id $rel_to_id; get;',
      ['rel'],
      { noCache }
    );
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(
      relations.map((r) => r.rel),
      'uses_from',
      'uses_to'
    ); // Roles with be set according to query specification
  });
  it.each(noCacheCases)('should find relations with role in Grakn (noCache = %s)', async (noCache) => {
    // Getting everything specifying all roles respect the roles of the query
    const relations = await find(
      'match $rel(uses_from:$from, uses_to:$to) isa uses, has internal_id $rel_id; ' +
        '$from has internal_id $rel_from_id; ' +
        '$to has internal_id $rel_to_id; ' +
        'get;',
      ['rel'],
      { noCache }
    );
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(
      relations.map((r) => r.rel),
      'uses_from',
      'uses_to'
    );
  });
  it.each(noCacheCases)('should find relations partial right roles in grakn (noCache = %s)', async (noCache) => {
    // Getting everything with partial roles respect the roles of the query
    const relations = await find(
      'match $rel($from, uses_to:$to) isa uses, has internal_id $rel_id; ' +
        '$from has internal_id $rel_from_id; ' +
        '$to has internal_id $rel_to_id; get;',
      ['rel'],
      { noCache }
    );
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(
      relations.map((r) => r.rel),
      'uses_from',
      'uses_to'
    );
  });
  it.each(noCacheCases)('should find relations partial left roles in grakn (noCache = %s)', async (noCache) => {
    // Getting everything with partial roles respect the roles of the query
    const relations = await find(
      'match $rel(uses_from:$from, $to) isa uses, has internal_id $rel_id; ' +
        '$from has internal_id $rel_from_id; ' +
        '$to has internal_id $rel_to_id; ' +
        'get;',
      ['rel'],
      { noCache }
    );
    expect(relations).not.toBeNull();
    expect(relations.length).toEqual(3);
    // eslint-disable-next-line prettier/prettier
    checkRoles(
      relations.map((r) => r.rel),
      'uses_from',
      'uses_to'
    );
  });
  it.each(noCacheCases)('should list relations (noCache = %s)', async (noCache) => {
    const stixCoreRelationships = await listRelations('stix-core-relationship', { noCache });
    expect(stixCoreRelationships).not.toBeNull();
    expect(stixCoreRelationships.edges.length).toEqual(24);
    const stixMetaRelationships = await listRelations('stix-meta-relationship', { noCache });
    expect(stixMetaRelationships).not.toBeNull();
    expect(stixMetaRelationships.edges.length).toEqual(135);
  });
  it.each(noCacheCases)('should list relations with roles (noCache = %s)', async (noCache) => {
    const stixRelations = await listRelations('uses', { noCache, fromRole: 'uses_from', toRole: 'uses_to' });
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(3);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromRole).toEqual('uses_from');
      expect(stixRelation.toRole).toEqual('uses_to');
    }
  });
  it.each(noCacheCases)('should list relations with id option (noCache = %s)', async (noCache) => {
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
  it.each(noCacheCases)('should list relations with from types option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const intrusionSet = await internalLoadEntityById('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    expect(intrusionSet.entity_type).toEqual('Intrusion-Set');
    const options = { noCache, fromId: intrusionSet.internal_id, fromTypes: ['Intrusion-Set'] };
    const stixRelations = await listRelations('targets', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(intrusionSet.internal_id);
    }
  });
  it.each(noCacheCases)('should list relations with to types option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const malware = await internalLoadEntityById('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, toTypes: ['Attack-Pattern'] };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line no-await-in-loop
      const toThing = await elLoadById(stixRelation.toId);
      expect(toThing.entity_type).toEqual('Attack-Pattern');
      expect(stixRelation.fromId).toEqual(malware.internal_id);
    }
  });
  it.each(noCacheCases)('should list relations with first and order filtering (noCache = %s)', async (noCache) => {
    // TODO @JRI Grakn pagination x 2
    const options = { first: 6, after: offsetToCursor(0), orderBy: 'created', orderMode: 'asc', noCache };
    const stixRelations = await listRelations('stix-core-relationship', options);
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(noCache ? 3 : 6);
    // Every relations must have natural ordering for from and to
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line camelcase
      const { fromRole, toRole, relationship_type: relationshipType } = stixRelation;
      expect(fromRole).toEqual(`${relationshipType}_from`);
      expect(toRole).toEqual(`${relationshipType}_to`);
    }
    const relation = head(stixRelations.edges).node;
    expect(relation.created).toEqual('2019-04-25T20:53:08.446Z');
    const from = await elLoadById(relation.fromId);
    expect(from.standard_id).toEqual('course-of-action--9fe13723-52c6-5a93-89a7-b06b2737af83');
    expect(from.stix_ids).toEqual(['course-of-action--ae56a49d-5281-45c5-ab95-70a1439c338e']);
    const to = await elLoadById(relation.toId);
    expect(to.stix_ids).toEqual(['attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17']);
  });
  it.each(noCacheCases)('should list relations ordered by relation (noCache = %s)', async (noCache) => {
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

    const options = { orderBy: 'rel_indicates.standard_id', orderMode: 'asc', noCache };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const first = head(stixRelations.edges).node;
    const second = last(stixRelations.edges).node;
    expect(first.stix_ids).toEqual(['relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02']);
    expect(second.stix_ids).toEqual(['relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de']);
  });
  it.each(noCacheCases)('should list relations with relation filtering (noCache = %s)', async (noCache) => {
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
    const indicator = await elLoadByStixId('indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079');
    const indicatorId = indicator.internal_id; // indicator -> www.xolod-teplo.ru
    const relationFilter = {
      relation: 'indicates',
      fromRole: 'indicates_to',
      toRole: 'indicates_from',
      id: indicatorId,
    };
    const options = { noCache, relationFilter };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = head(stixRelations.edges).node;
    expect(relation.standard_id).toEqual('relationship--e355c654-884f-597b-a457-8bb07d50c352');
    expect(relation.stix_ids).toEqual(['relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de']);
    expect(relation.fromRole).toEqual('uses_from');
    expect(relation.toRole).toEqual('uses_to');
    expect(relation.created).toEqual('2020-03-01T14:05:16.797Z');
  });
  it.each(noCacheCases)('should list relations with relation filtering on report (noCache = %s)', async (noCache) => {
    const report = await elLoadByStixId('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const relationFilter = {
      relation: 'object',
      fromRole: 'object_to',
      toRole: 'object_from',
      id: report.internal_id,
    };
    const args = { noCache, relationFilter };
    const stixRelations = await listRelations('stix-core-relationship', args);
    // TODO Ask Julien
    expect(stixRelations.edges.length).toEqual(11);
    const relation = await elLoadByStixId('relationship--b703f822-f6f0-4d96-9c9b-3fc0bb61e69c');
    const argsWithRelationId = {
      noCache,
      relationFilter: assoc('relationId', relation.internal_id, relationFilter),
    };
    const stixRelationsWithInternalId = await listRelations('stix-core-relationship', argsWithRelationId);
    expect(stixRelationsWithInternalId.edges.length).toEqual(1);
  });
  it.each(noCacheCases)('should list relations with to attribute filtering (noCache = %s)', async (noCache) => {
    const options = { orderBy: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`, orderMode: 'asc', noCache };
    const stixRelations = await listRelations('uses', options);
    // TODO Fix that test
    expect(stixRelations).not.toBeNull();
  });
  it.each(noCacheCases)('should list relations with search (noCache = %s)', async (noCache) => {
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, search: 'Spear phishing' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const relTargets = await Promise.all(map((s) => elLoadById(s.node.toId), stixRelations.edges));
    for (let index = 0; index < relTargets.length; index += 1) {
      const target = relTargets[index];
      expect(target.name).toEqual(expect.stringContaining('Spear phishing'));
    }
  });
  it.each(noCacheCases)('should list relations start time (noCache = %s)', async (noCache) => {
    // Uses relations first seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-28T23:00:00.000Z"
    const options = { noCache, startTimeStart: '2020-02-29T22:00:00.000Z', stopTimeStop: '2020-02-29T23:30:00.000Z' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
  });
  it.each(noCacheCases)('should list relations stop time (noCache = %s)', async (noCache) => {
    // Uses relations last seen
    // 0 = "2020-02-29T23:00:00.000Z" | 1 = "2020-02-29T23:00:00.000Z" | 2 = "2020-02-29T23:00:00.000Z"
    let options = { noCache, startTimeStart: '2020-02-29T23:00:00.000Z', stopTimeStop: '2020-02-29T23:00:00.000Z' };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
    options = { noCache, startTimeStart: '2020-02-29T22:59:59.000Z', stopTimeStop: '2020-02-29T23:00:01.000Z' };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
  });
  it.each(noCacheCases)('should list relations with confidence (noCache = %s)', async (noCache) => {
    const options = { noCache, confidences: [20] };
    const stixRelations = await listRelations('indicates', options);
    expect(stixRelations.edges.length).toEqual(2);
  });
  it.each(noCacheCases)('should list relations with filters (noCache = %s)', async (noCache) => {
    const key = `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`;
    let filters = [{ key, operator: 'match', values: ['malicious'] }];
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let options = { noCache, fromId: malware.internal_id, filters };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = head(stixRelations.edges).node;
    const target = await elLoadById(relation.toId);
    expect(target.name).toEqual(expect.stringContaining('malicious'));
    // Test with exact match
    filters = [{ key, values: ['malicious'] }];
    options = { noCache, fromId: malware.internal_id, filters };
    stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(0);
  });
  it.each(noCacheCases)('should list sightings (noCache = %s)', async (noCache) => {
    const stixSightings = await listRelations('stix-sighting-relationship', { noCache });
    expect(stixSightings).not.toBeNull();
    expect(stixSightings.edges.length).toEqual(2);
  });
  it.each(noCacheCases)('should list sightings with id option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const relationship = await elLoadByStixId('relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9');
    const options = { noCache, fromId: relationship.internal_id };
    const thing = await internalLoadEntityById(relationship.internal_id);
    const stixSightings = await listRelations('stix-sighting-relationship', options);
    for (let index = 0; index < stixSightings.edges.length; index += 1) {
      const stixSighting = stixSightings.edges[index].node;
      expect(stixSighting.fromId).toEqual(thing.grakn_id);
    }
  });
});

describe('Grakn relations with inferences', () => {
  it('should inference explanation correctly resolved', async () => {
    await inferenceEnable(PART_OF_TARGETS_RULE);
    // Find the Grakn ID of the connections to build the inferred relation
    // In the data loaded its APT41 (intrusion-set) < target > Southwire (organization)
    const apt28 = await internalLoadEntityById('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const southwire = await internalLoadEntityById('identity--5a510e41-5cb2-45cc-a191-a4844ea0a141');
    // Build the inferred relation for testing
    const inference = `{ $rel(targets_from: $from, targets_to: $to) isa targets;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${apt28.internal_id}"; 
    $to has internal_id "${southwire.internal_id}"; };`;
    const inferenceId = Buffer.from(inference).toString('base64');
    const relation = await getRelationInferredById(inferenceId);
    expect(relation).not.toBeNull();
    expect(relation.relationship_type).toEqual('targets');
    expect(relation.inferred).toBeTruthy();
    expect(relation.fromRole).toEqual('targets_from');
    expect(relation.toRole).toEqual('targets_to');
    expect(relation.inferences).not.toBeNull();
    expect(relation.inferences.edges.length).toEqual(2);
    const aggregationMap = new Map(relation.inferences.edges.map((i) => [head(i.node.external_stix_id), i.node]));
    // relationship--3541149d-1af6-4688-993c-dc32c7ee3880
    // APT41 > intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
    // Allied Universal > identity--c017f212-546b-4f21-999d-97d3dc558f7b
    const firstSegment = aggregationMap.get('relationship--3541149d-1af6-4688-993c-dc32c7ee3880');
    expect(firstSegment).not.toBeUndefined();
    expect(firstSegment.internal_id).toEqual('36d591b6-54b9-4152-ab89-79c7dad709f7');
    expect(firstSegment.fromRole).toEqual('targets_from');
    expect(firstSegment.toRole).toEqual('targets_to');
    // relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7
    // Allied Universal > identity--c017f212-546b-4f21-999d-97d3dc558f7b
    // Southwire > identity--5a510e41-5cb2-45cc-a191-a4844ea0a141
    const secondSegment = aggregationMap.get('relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7');
    expect(secondSegment).not.toBeUndefined();
    expect(secondSegment.internal_id).toEqual('b7a4d86f-220e-412a-8135-6e9fb9f7b296');
    expect(secondSegment.fromRole).toEqual('part_of');
    expect(secondSegment.toRole).toEqual('gather');
    // Disable the rule
    await inferenceDisable(PART_OF_TARGETS_RULE);
  });
});

describe('Grakn element loader', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should load entity by id - internal (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByStixId('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    let element = await internalLoadEntityById(internalId, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
    // Correct type
    element = await loadEntityById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    // Wrong type
    element = await loadEntityById(internalId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { noCache });
    expect(element).toBeNull();
  });
  it.each(noCacheCases)('should load entity by id (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByStixId('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    const loadPromise = loadEntityById(internalId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadEntityById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load entity by stix id (noCache = %s)', async (noCache) => {
    // No type
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const loadPromise = loadEntityById(stixId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadEntityById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.standard_id).toEqual('report--8f892e04-0c8d-5f02-af2c-423cef12a082');
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load relation by id (noCache = %s)', async (noCache) => {
    // No type
    const relation = await elLoadByStixId('relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02');
    const relationId = relation.internal_id;
    const loadPromise = loadRelationById(relationId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadRelationById(relationId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(relationId);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load relation by stix id (noCache = %s)', async (noCache) => {
    const stixId = 'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02';
    const loadPromise = loadRelationById(stixId, null, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadRelationById(stixId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.standard_id).toEqual('relationship--6a7c8d6b-de21-5576-b857-7474e29922c0');
    expect(element.stix_ids).toEqual([stixId]);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load by grakn id for multiple attributes (noCache = %s)', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const identity = await loadEntityById(stixId, ENTITY_TYPE_IDENTITY_ORGANIZATION, { noCache });
    expect(identity).not.toBeNull();
    expect(identity.aliases).not.toBeNull();
    expect(identity.aliases.length).toEqual(2);
    expect(identity.aliases.includes('Computer Incident')).toBeTruthy();
    expect(identity.aliases.includes('Incident')).toBeTruthy();
  });
});

describe('Grakn attribute updated and indexed correctly', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should entity report attribute updated (noCache = %s)', async (noCache) => {
    let entityTypes = await findAllAttributes({ type: 'report_class' });
    expect(entityTypes).not.toBeNull();
    // expect(entityTypes.edges.length).toEqual(2);
    let typeMap = new Map(entityTypes.edges.map((i) => [i.node.value, i]));
    const threatReportAttribute = typeMap.get('Threat Report');
    expect(threatReportAttribute).not.toBeUndefined();
    const attributeGraknId = threatReportAttribute.node.id;
    // 01. Get the report directly and test if type is "Threat report".
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    let report = await loadEntityById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_class).toEqual('Threat Report');
    // 02. Update attribute "Threat report" to "Threat test"
    let updatedAttribute = await attributeUpdate(attributeGraknId, {
      type: 'report_class',
      value: 'Threat Report',
      newValue: 'Threat Test',
    });
    expect(updatedAttribute).not.toBeNull();
    // 03. Get the report directly and test if type is Threat test
    report = await loadEntityById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['Threat Test']);
    // 04. Back to original configuration
    entityTypes = await findAllAttributes({ type: 'report_class' });
    typeMap = new Map(entityTypes.edges.map((i) => [i.node.value, i]));
    updatedAttribute = await attributeUpdate(typeMap.get('Threat Test').node.id, {
      type: 'report_class',
      value: 'Threat Test',
      newValue: 'Threat Report',
    });
    expect(updatedAttribute).not.toBeNull();
    report = await loadEntityById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_class).toEqual('Threat Report');
  });
  it.each(noCacheCases)('should relation report attribute updated (noCache = %s)', async (noCache) => {
    // Test with relation update
    let relationshipTypes = await findAllAttributes({ type: 'role_played' });
    expect(relationshipTypes).not.toBeNull();
    expect(relationshipTypes.edges.length).toEqual(3);
    let typeMap = new Map(relationshipTypes.edges.map((i) => [i.node.value, i]));
    const relationAttribute = typeMap.get('Unknown');
    expect(relationAttribute).not.toBeUndefined();
    const attributeGraknId = relationAttribute.node.id;
    // 01. Get the relation relationship--c32d553c-e22f-40ce-93e6-eb62dd145f3b and test if type is "Unknown"
    const stixId = 'relationship--c32d553c-e22f-40ce-93e6-eb62dd145f3b';
    let relation = await loadRelationById(stixId, 'indicates', { noCache });
    expect(relation).not.toBeNull();
    expect(relation.role_played).toEqual('Unknown');
    // 02. Update attribute "Unknown" to "For test"
    const updatedAttribute = await attributeUpdate(attributeGraknId, {
      type: 'role_played',
      value: 'Unknown',
      newValue: 'For test',
    });
    expect(updatedAttribute).not.toBeNull();
    // 03. Get the relation directly and test if type is "For test"
    relation = await loadRelationById(stixId, 'indicates', { noCache });
    expect(relation).not.toBeNull();
    expect(relation.role_played).toEqual('For test');
    // 04. Back to original configuration
    relationshipTypes = await findAllAttributes({ type: 'role_played' });
    expect(relationshipTypes.edges.length).toEqual(3);
    typeMap = new Map(relationshipTypes.edges.map((i) => [i.node.value, i]));
    await attributeUpdate(typeMap.get('For test').node.id, {
      type: 'role_played',
      value: 'For test',
      newValue: 'Unknown',
    });
    relation = await loadRelationById(stixId, 'indicates', { noCache });
    expect(relation).not.toBeNull();
    expect(relation.role_played).toEqual('Unknown');
  });
});

describe('Grakn entities time series', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should published entity time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const options = {
      field: 'published',
      operation: 'count',
      interval: 'month',
      startDate: '2019-09-23T00:00:00.000+01:00',
      endDate: '2020-04-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesEntities('Stix-Domain-Object', [], options);
    expect(series.length).toEqual(8);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-02-29T23:00:00.000Z')).toEqual(1);
  });
  it.each(noCacheCases)('should start time relation time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const filters = [{ isRelation: true, type: 'attributed-to', value: '82316ffd-a0ec-4519-a454-6566f8f5676c' }];
    const options = {
      field: 'start_time',
      operation: 'count',
      interval: 'month',
      startDate: '2020-01-01T00:00:00+01:00',
      endDate: '2021-01-01T00:00:00+01:00',
      noCache,
    };
    const series = await timeSeriesEntities('Campaign', filters, options);
    expect(series.length).toEqual(13);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(1);
  });
  it.each(noCacheCases)('should local filter time series (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, interval, inferred = false } = options;
    const filters = [{ type: 'name', value: 'A new campaign' }];
    const options = {
      field: 'start_time',
      operation: 'count',
      interval: 'month',
      startDate: '2020-01-01T00:00:00+01:00',
      endDate: '2020-10-01T00:00:00+02:00',
      noCache,
    };
    const series = await timeSeriesEntities('Stix-Domain-Object', filters, options);
    expect(series.length).toEqual(10);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(1);
  });
});

describe('Grakn relations time series', () => {
  // const { startDate, endDate, operation, relationship_type, field, interval, fromId, inferred = false } = options;
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should relations first seen time series (noCache = %s)', async (noCache) => {
    // relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02 > 2020-02-29T23:00:00.000Z
    // relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de > 2020-02-29T23:00:00.000Z
    // relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3 > 2020-02-28T23:00:00.000Z
    const options = {
      relationship_type: 'uses',
      field: 'start_time',
      operation: 'count',
      interval: 'month',
      startDate: '2019-09-23T00:00:00.000+01:00',
      endDate: '2020-04-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesRelations(options);
    expect(series.length).toEqual(8);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020-01-31T23:00:00.000Z')).toEqual(3);
  });
  it.each(noCacheCases)('should relations with fromId time series (noCache = %s)', async (noCache) => {
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      relationship_type: 'uses',
      field: 'start_time',
      operation: 'count',
      interval: 'year',
      startDate: '2018-09-23T00:00:00.000+01:00',
      endDate: '2020-06-04T00:00:00.000+01:00',
      noCache,
    };
    const series = await timeSeriesRelations(options);
    expect(series.length).toEqual(3);
    const aggregationMap = new Map(series.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019-12-31T23:00:00.000Z')).toEqual(3);
  });
});

describe('Grakn entities distribution', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should entity distribution (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const options = { field: 'entity_type', operation: 'count', limit: 20, noCache };
    const distribution = await distributionEntities('Stix-Domain', [], options);
    expect(distribution.length).toEqual(19);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(2);
    expect(aggregationMap.get('marking-definition')).toEqual(6);
    expect(aggregationMap.get('external-reference')).toEqual(7);
  });
  it.each(noCacheCases)('should entity distribution filters (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { field: 'entity_type', operation: 'count', limit: 20, noCache };
    const start = '2020-02-29T22:29:00.000Z';
    const end = '2020-02-29T22:31:00.000Z';
    const relationFilter = {
      isRelation: true,
      type: 'uses',
      from: 'usage',
      to: 'user',
      value: malware.internal_id,
      start,
      end,
    };
    const filters = [relationFilter];
    const distribution = await distributionEntities('Stix-Domain-Object', filters, options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('attack-pattern')).toEqual(1);
  });
  it.each(noCacheCases)('should entity distribution with date filtering (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const options = {
      field: 'entity_type',
      operation: 'count',
      limit: 20,
      startDate: '2018-03-01T00:00:00+01:00',
      endDate: '2018-03-02T00:00:00+01:00',
      noCache,
    };
    const distribution = await distributionEntities('Stix-Domain-Object', [], options);
    expect(distribution.length).toEqual(0);
  });
});

describe('Grakn relations distribution', () => {
  // Malware Paradise Ransomware
  // --> attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc
  // ----------- relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02 > first_seen: 2020-02-29T23:00:00.000Z,
  // --> attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
  // ----------- relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de > first_seen: 2020-02-29T23:00:00.000Z
  // <-- intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
  // ----------- relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3 > first_seen: 2020-02-28T23:00:00.000Z
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should relation distribution (noCache = %s)', async (noCache) => {
    // const { limit = 50, order, noCache = false, inferred = false } = options;
    // const { startDate, endDate, relationship_type, toTypes, fromId, field, operation } = options;
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      relationship_type: 'uses',
      field: 'entity_type',
      operation: 'count',
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(2);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('attack-pattern')).toEqual(2);
    expect(aggregationMap.get('intrusion-set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution dates filtered (noCache = %s)', async (noCache) => {
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      field: 'entity_type',
      operation: 'count',
      startDate: '2020-02-28T22:59:00.000Z',
      endDate: '2020-02-28T23:01:00.000Z',
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('intrusion-set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution filtered by to (noCache = %s)', async (noCache) => {
    const malware = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = {
      fromId: malware.internal_id,
      field: 'entity_type',
      operation: 'count',
      toTypes: ['Attack-Pattern'],
      noCache,
    };
    const distribution = await distributionRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('attack-pattern')).toEqual(2);
  });
});

describe('Grakn entities distribution through relation', () => {
  // const { limit = 10, order, inferred = false } = options;
  // const { relationship_type, remoterelationship_type, toType, fromId, field, operation } = options;
  // campaign--92d46985-17a6-4610-8be8-cc70c82ed214
  it('should relation distribution filtered by to (noCache = %s)', async () => {
    const campaign = await elLoadByStixId('campaign--92d46985-17a6-4610-8be8-cc70c82ed21');
    const options = {
      fromId: campaign.internal_id,
      field: 'name',
      operation: 'count',
      relationshipType: 'object',
      toType: 'Report',
      remoteRelationshipType: 'created-by',
    };
    const distribution = await distributionEntitiesThroughRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('ANSSI')).toEqual(1);
  });
});
