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
  internalLoadById,
  listEntities,
  listRelations,
  load,
  loadById,
  monthFormat,
  now,
  patchAttribute,
  prepareDate,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  querySubTypes,
  REL_CONNECTED_SUFFIX,
  sinceNowInMinutes,
  timeSeriesEntities,
  timeSeriesRelations,
  yearFormat,
} from '../../../src/database/grakn';
import { attributeUpdate, findAll as findAllAttributes } from '../../../src/domain/attribute';
import { INDEX_STIX_DOMAIN_OBJECTS, utcDate } from '../../../src/database/utils';
import { PART_OF_TARGETS_RULE, inferenceDisable, inferenceEnable } from '../../../src/domain/inference';
import { elLoadByIds } from '../../../src/database/elasticSearch';
import { ADMIN_USER } from '../../utils/testQuery';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
} from '../../../src/schema/stixDomainObject';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, REL_INDEX_PREFIX } from '../../../src/schema/general';
import { RELATION_MITIGATES } from '../../../src/schema/stixCoreRelationship';

describe('Grakn basic and utils', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
    expect(getGraknVersion()).toEqual('1.8.3');
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
        .query(`match $c isa Connector, has internal_id "${connectorId}"; delete $c isa Connector;`) //
        .then((it) => it.collect());
    });
    expect(deleteData).not.toBeNull();
    expect(deleteData.length).toEqual(1);
    expect(head(deleteData).message()).toEqual('Deleted facts from 1 matched answers.');
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
      'match $m isa Malware; $m has x_opencti_stix_ids "malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88", has internal_id $m_id; get;';
    const malware = await load(query, ['m'], { noCache });
    expect(malware.m).not.toBeNull();
    expect(malware.m.x_opencti_stix_ids).toEqual(['malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88']);
    expect(malware.m.standard_id).toEqual('malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85');
  });
  it('should load subTypes values', async () => {
    const stixObservableSubTypes = await querySubTypes('Stix-Cyber-Observable');
    expect(stixObservableSubTypes).not.toBeNull();
    expect(stixObservableSubTypes.edges.length).toEqual(26);
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
    expect(await countObjects('Capability')).toEqual(20);
    expect(await countObjects('Stix-Cyber-Observable')).toEqual(1);
    expect(await countObjects('Basic-Object')).toEqual(91);

    // Relations
  });
});

describe('Grakn attribute updater', () => {
  const noCacheCases = [[true], [false]];
  it('should update fail for unknown attributes', async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const input = { observable_value: 'test' };
    const update = patchAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, input);
    expect(update).rejects.toThrow();
  });
  it('should update dont do anything if already the same', async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const campaignId = campaign.internal_id;
    const patch = { description: 'A test campaign' };
    const update = await patchAttribute(ADMIN_USER, campaignId, ENTITY_TYPE_CAMPAIGN, patch);
    expect(update.internal_id).toEqual(campaignId);
  });
  it.each(noCacheCases)('should update date with dependencies', async (noCache) => {
    const stixId = 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214';
    let campaign = await internalLoadById(stixId, { noCache });
    const campaignId = campaign.internal_id;
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    const type = 'Stix-Domain-Object';
    let patch = { first_seen: '2020-02-20T08:45:43.366Z' };
    let update = await patchAttribute(ADMIN_USER, campaignId, type, patch);
    expect(update.internal_id).toEqual(campaignId);
    campaign = await internalLoadById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-20T08:45:43.366Z');
    expect(campaign.i_first_seen_day).toEqual('2020-02-20');
    expect(campaign.i_first_seen_month).toEqual('2020-02');
    expect(campaign.i_first_seen_year).toEqual('2020');
    // Value back to before
    patch = { first_seen: '2020-02-27T08:45:43.365Z' };
    update = await patchAttribute(ADMIN_USER, campaignId, type, patch);
    expect(update.internal_id).toEqual(campaignId);
    campaign = await internalLoadById(stixId, { noCache });
    expect(campaign.first_seen).toEqual('2020-02-27T08:45:43.365Z');
    expect(campaign.i_first_seen_day).toEqual('2020-02-27');
  });
  it.each(noCacheCases)('should update numeric', async (noCache) => {
    const stixId = 'relationship--efc9bbb8-e606-4fb1-83ae-d74690fd0416';
    let relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    const relationId = relation.internal_id;
    // expect(relation.confidence).toEqual(1);
    let patch = { confidence: 5 };
    await patchAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, patch, { noCache });
    relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    expect(relation.confidence).toEqual(5);
    // Value back to before
    patch = { confidence: 1 };
    await patchAttribute(ADMIN_USER, relationId, RELATION_MITIGATES, patch, { noCache });
    relation = await loadById(stixId, ABSTRACT_STIX_CORE_RELATIONSHIP, { noCache });
    expect(relation.confidence).toEqual(1);
  });
  it.each(noCacheCases)('should update multivalued attribute', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const type = 'Stix-Domain-Object';
    let identity = await internalLoadById(stixId, { noCache });
    const identityId = identity.internal_id;
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
    let patch = { x_opencti_aliases: ['Computer', 'Test', 'Grakn'] };
    await patchAttribute(ADMIN_USER, identityId, type, patch);
    identity = await internalLoadById(stixId, { noCache });
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer', 'Test', 'Grakn'].sort());
    // Value back to before
    patch = { x_opencti_aliases: ['Computer Incident', 'Incident'] };
    await patchAttribute(ADMIN_USER, identityId, type, patch);
    identity = await internalLoadById(stixId, { noCache });
    expect(identity.x_opencti_aliases.sort()).toEqual(['Computer Incident', 'Incident'].sort());
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
    const dataMap = new Map(malwares.edges.map((i) => [head(i.node.x_opencti_stix_ids), i.node]));
    const malware = dataMap.get('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware.grakn_id).not.toBeNull();
    expect(malware.standard_id).toEqual('malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714');
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
    expect(head(attacks.edges).node.standard_id).toEqual('attack-pattern--acdfc109-e0fd-5711-839b-a37ee49529b9');
    expect(head(attacks.edges).node.x_opencti_stix_ids).toEqual([
      'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc',
    ]);
  });
  it.each(noCacheCases)('should list multiple entities with attribute filters (noCache = %s)', async (noCache) => {
    const identity = await elLoadByIds('identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5');
    const filters = [{ key: `rel_created-by.internal_id`, values: [identity.internal_id] }];
    const options = { filters, noCache };
    const entities = await listEntities(['Attack-Pattern', 'Intrusion-Set'], ['name'], options);
    expect(entities).not.toBeNull();
    expect(entities.edges.length).toEqual(3);
  });

  const relationFilterUseCases = [
    ['name', 'The MITRE Corporation', true],
    ['name', 'The MITRE Corporation', false],
    ['x_opencti_stix_ids', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', true],
    ['x_opencti_stix_ids', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', false],
  ];
  it.each(relationFilterUseCases)(
    'should list entities with ref relation %s=%s filters (noCache = %s)',
    async (field, val, noCache) => {
      const filters = [{ key: `rel_created-by.${field}`, values: [val], toRole: 'created-by_to' }];
      const options = { filters, noCache };
      const entities = await listEntities(['Stix-Domain-Object'], ['name'], options);
      expect(entities).not.toBeNull();
      expect(entities.edges.length).toEqual(5);
      const aggregationMap = new Map(entities.edges.map((i) => [head(i.node.x_opencti_stix_ids || ['fake']), i.node]));
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
    const aggregationMap = new Map(data.map((i) => [head(i.m.x_opencti_stix_ids), i.m]));
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
    const relations = await find('match $rel isa uses; get;', ['rel'], { noCache });
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
    expect(stixCoreRelationships.edges.length).toEqual(21);
    const stixMetaRelationships = await listRelations('stix-meta-relationship', { noCache });
    expect(stixMetaRelationships).not.toBeNull();
    expect(stixMetaRelationships.edges.length).toEqual(128);
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
    const thing = await internalLoadById('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    const stixRelations = await listRelations('uses', options);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      expect(stixRelation.fromId).toEqual(thing.grakn_id);
    }
  });
  it.each(noCacheCases)('should list relations with from types option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const intrusionSet = await internalLoadById('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
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
    const malware = await internalLoadById('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, toTypes: ['Attack-Pattern'] };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    for (let index = 0; index < stixRelations.edges.length; index += 1) {
      const stixRelation = stixRelations.edges[index].node;
      // eslint-disable-next-line no-await-in-loop
      const toThing = await elLoadByIds(stixRelation.toId);
      expect(toThing.entity_type).toEqual('Attack-Pattern');
      expect(stixRelation.fromId).toEqual(malware.internal_id);
    }
  });
  it.each(noCacheCases)('should list relations with first and order filtering (noCache = %s)', async (noCache) => {
    const options = { first: 6, after: offsetToCursor(0), orderBy: 'created', orderMode: 'asc', noCache };
    const stixRelations = await listRelations('stix-core-relationship', options);
    expect(stixRelations).not.toBeNull();
    expect(stixRelations.edges.length).toEqual(6);
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
    expect(first.x_opencti_stix_ids).toEqual(['relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02']);
    expect(second.x_opencti_stix_ids).toEqual(['relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de']);
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
    const indicator = await elLoadByIds('indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079');
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
    expect(relation.x_opencti_stix_ids).toEqual(['relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de']);
    expect(relation.fromRole).toEqual('uses_from');
    expect(relation.toRole).toEqual('uses_to');
    expect(relation.created).toEqual('2020-03-01T14:05:16.797Z');
  });
  it.each(noCacheCases)('should list relations with relation filtering on report (noCache = %s)', async (noCache) => {
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
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
    const relation = await elLoadByIds('relationship--b703f822-f6f0-4d96-9c9b-3fc0bb61e69c');
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
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { noCache, fromId: malware.internal_id, search: 'Spear phishing' };
    const stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(2);
    const relTargets = await Promise.all(map((s) => elLoadByIds(s.node.toId), stixRelations.edges));
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
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let options = { noCache, fromId: malware.internal_id, filters };
    let stixRelations = await listRelations('uses', options);
    expect(stixRelations.edges.length).toEqual(1);
    const relation = head(stixRelations.edges).node;
    const target = await elLoadByIds(relation.toId);
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
    expect(stixSightings.edges.length).toEqual(3);
  });
  it.each(noCacheCases)('should list sightings with id option (noCache = %s)', async (noCache) => {
    // Just id specified,
    // "name": "Paradise Ransomware"
    const relationship = await elLoadByIds('relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9');
    const options = { noCache, fromId: relationship.internal_id };
    const thing = await internalLoadById(relationship.internal_id);
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
    const apt28Id = 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7';
    const apt28 = await internalLoadById(apt28Id, { noCache: true });
    const southwireId = 'identity--5a510e41-5cb2-45cc-a191-a4844ea0a141';
    const southwire = await internalLoadById(southwireId, { noCache: true });
    // Build the inferred relation for testing
    const inference = `{ $rel(targets_from: $from, targets_to: $to) isa targets; $from id ${apt28.grakn_id}; $to id ${southwire.grakn_id}; };`;
    const inferenceId = Buffer.from(inference).toString('base64');
    const relation = await getRelationInferredById(inferenceId);
    expect(relation).not.toBeNull();
    expect(relation.relationship_type).toEqual('targets');
    expect(relation.inferred).toBeTruthy();
    expect(relation.fromRole).toEqual('targets_from');
    expect(relation.toRole).toEqual('targets_to');
    expect(relation.inferences).not.toBeNull();
    expect(relation.inferences.edges.length).toEqual(2);
    const aggregationMap = new Map(relation.inferences.edges.map((i) => [head(i.node.x_opencti_stix_ids), i.node]));
    // relationship--3541149d-1af6-4688-993c-dc32c7ee3880
    // APT41 > intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
    // Allied Universal > identity--c017f212-546b-4f21-999d-97d3dc558f7b
    const firstSegment = aggregationMap.get('relationship--3541149d-1af6-4688-993c-dc32c7ee3880');
    expect(firstSegment).not.toBeUndefined();
    expect(firstSegment.fromRole).toEqual('targets_from');
    expect(firstSegment.toRole).toEqual('targets_to');
    // relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7
    // Allied Universal > identity--c017f212-546b-4f21-999d-97d3dc558f7b
    // Southwire > identity--5a510e41-5cb2-45cc-a191-a4844ea0a141
    const secondSegment = aggregationMap.get('relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7');
    expect(secondSegment).not.toBeUndefined();
    expect(secondSegment.fromRole).toEqual('part-of_from');
    expect(secondSegment.toRole).toEqual('part-of_to');
    // Disable the rule
    await inferenceDisable(PART_OF_TARGETS_RULE);
  });
});

describe('Grakn element loader', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should load entity by id - internal (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    let element = await internalLoadById(internalId, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
    // Correct type
    element = await loadById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    // Wrong type
    element = await loadById(internalId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { noCache });
    expect(element).toBeUndefined();
  });
  it.each(noCacheCases)('should load entity by id (noCache = %s)', async (noCache) => {
    // No type
    const report = await elLoadByIds('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const internalId = report.internal_id;
    const loadPromise = loadById(internalId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(internalId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(internalId);
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load entity by stix id (noCache = %s)', async (noCache) => {
    // No type
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const loadPromise = loadById(stixId, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(element).not.toBeNull();
    expect(element.standard_id).toEqual('report--f3e554eb-60f5-587c-9191-4f25e9ba9f32');
    expect(element.name).toEqual('A demo report for testing purposes');
  });
  it.each(noCacheCases)('should load relation by id (noCache = %s)', async (noCache) => {
    // No type
    const relation = await elLoadByIds('relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02');
    const relationId = relation.internal_id;
    const loadPromise = loadById(relationId, null, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(relationId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.id).toEqual(relationId);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load relation by stix id (noCache = %s)', async (noCache) => {
    const stixId = 'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02';
    const loadPromise = loadById(stixId, null, { noCache });
    expect(loadPromise).rejects.toThrow();
    const element = await loadById(stixId, 'uses', { noCache });
    expect(element).not.toBeNull();
    expect(element.x_opencti_stix_ids).toEqual([stixId]);
    expect(element.confidence).toEqual(3);
  });
  it.each(noCacheCases)('should load by grakn id for multiple attributes (noCache = %s)', async (noCache) => {
    const stixId = 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132';
    const identity = await loadById(stixId, ENTITY_TYPE_IDENTITY_ORGANIZATION, { noCache });
    expect(identity).not.toBeNull();
    expect(identity.x_opencti_aliases).not.toBeNull();
    expect(identity.x_opencti_aliases.length).toEqual(2);
    expect(identity.x_opencti_aliases.includes('Computer Incident')).toBeTruthy();
    expect(identity.x_opencti_aliases.includes('Incident')).toBeTruthy();
  });
});

describe('Grakn attribute updated and indexed correctly', () => {
  const noCacheCases = [[true], [false]];
  it.each(noCacheCases)('should entity report attribute updated (noCache = %s)', async (noCache) => {
    let entityTypes = await findAllAttributes({ type: 'report_types' });
    expect(entityTypes).not.toBeNull();
    expect(entityTypes.edges.length).toEqual(2);
    let typeMap = new Map(entityTypes.edges.map((i) => [i.node.value, i]));
    const threatReportAttribute = typeMap.get('threat-report');
    expect(threatReportAttribute).not.toBeUndefined();
    const attributeGraknId = threatReportAttribute.node.id;
    // 01. Get the report directly and test if type is "Threat report".
    const stixId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    let report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-report']);
    // 02. Update attribute "Threat report" to "Threat test"
    let updatedAttribute = await attributeUpdate(attributeGraknId, {
      type: 'report_types',
      value: 'threat-report',
      newValue: 'threat-test',
    });
    expect(updatedAttribute).not.toBeNull();
    // 03. Get the report directly and test if type is Threat test
    report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-test']);
    // 04. Back to original configuration
    entityTypes = await findAllAttributes({ type: 'report_types' });
    typeMap = new Map(entityTypes.edges.map((i) => [i.node.value, i]));
    updatedAttribute = await attributeUpdate(typeMap.get('threat-test').node.id, {
      type: 'report_types',
      value: 'threat-test',
      newValue: 'threat-report',
    });
    expect(updatedAttribute).not.toBeNull();
    report = await loadById(stixId, ENTITY_TYPE_CONTAINER_REPORT, { noCache });
    expect(report).not.toBeNull();
    expect(report.report_types).toEqual(['threat-report']);
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
    const intrusionSet = await elLoadByIds('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const filters = [{ isRelation: true, type: 'attributed-to', value: intrusionSet.internal_id }];
    const options = {
      field: 'first_seen',
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
      field: 'first_seen',
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
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
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
    const distribution = await distributionEntities('Stix-Domain-Object', [], options);
    expect(distribution.length).toEqual(17);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Malware')).toEqual(2);
    expect(aggregationMap.get('Campaign')).toEqual(1);
  });
  it.each(noCacheCases)('should entity distribution filters (noCache = %s)', async (noCache) => {
    // const { startDate, endDate, operation, field, inferred, noCache } = options;
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const options = { field: 'entity_type', operation: 'count', limit: 20, noCache };
    const start = '2020-02-28T22:59:00.000Z';
    const end = '2020-02-28T23:01:00.000Z';
    const relationFilter = {
      isRelation: true,
      type: 'uses',
      from: 'uses_from',
      to: 'uses_to',
      value: malware.internal_id,
      start,
      end,
    };
    const filters = [relationFilter];
    const distribution = await distributionEntities('Stix-Domain-Object', filters, options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
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
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
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
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution dates filtered (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
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
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });
  it.each(noCacheCases)('should relation distribution filtered by to (noCache = %s)', async (noCache) => {
    const malware = await elLoadByIds('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
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
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
  });
});

describe('Grakn entities distribution through relation', () => {
  // const { limit = 10, order, inferred = false } = options;
  // const { relationship_type, remoterelationship_type, toType, fromId, field, operation } = options;
  // campaign--92d46985-17a6-4610-8be8-cc70c82ed214
  it('should relation distribution filtered by to (noCache = %s)', async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const options = {
      fromId: campaign.internal_id,
      field: 'name',
      operation: 'count',
      relationshipType: 'object',
      toTypes: ['Report'],
      remoteRelationshipType: 'created-by',
    };
    const distribution = await distributionEntitiesThroughRelations(options);
    expect(distribution.length).toEqual(1);
    const aggregationMap = new Map(distribution.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('ANSSI')).toEqual(1);
  });
});
