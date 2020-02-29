/* eslint-disable no-underscore-dangle */
import { assoc, find, propEq, map, head } from 'ramda';
import {
  elAggregationCount,
  elCount,
  elCreateIndexes,
  elDeleteIndexes,
  elIndex,
  elIndexExists,
  elIsAlive,
  elLoadByGraknId,
  elLoadById,
  elLoadByStixId,
  elPaginate,
  elVersion,
  forceNoCache,
  INDEX_STIX_ENTITIES
} from '../../../src/database/elasticSearch';

describe('Elasticsearch configuration test', () => {
  it('should configuration correct', () => {
    expect(elIsAlive()).resolves.toBeTruthy();
    expect(elVersion()).resolves.toContain('7.5');
    expect(forceNoCache()).toBeFalsy();
    expect(elIndexExists(INDEX_STIX_ENTITIES)).toBeTruthy();
  });
  it('should manage index', async () => {
    // Create index
    const createdIndices = await elCreateIndexes(['test_index']);
    expect(createdIndices.length).toEqual(1);
    expect(head(createdIndices).body.acknowledged).toBeTruthy();
    expect(head(createdIndices).body.index).toEqual('test_index');
    // Remove index
    const deletedIndices = await elDeleteIndexes(['test_index']);
    expect(deletedIndices.length).toEqual(1);
    expect(head(deletedIndices).body.acknowledged).toBeTruthy();
  });
});

describe('Elasticsearch document loader', () => {
  beforeAll(async () => {
    await elCreateIndexes(['test_index']);
  });
  afterAll(async () => {
    await elDeleteIndexes(['test_index']);
  });
  it('should create and retrieve document', async () => {
    // Index an element and try to retrieve the data
    const graknId = 'V23181';
    const stixId = 'campaign--aae8b913-564b-405e-a9c1-5e5ea6c60259';
    const internalIdKey = '867d03f4-be73-44f6-82d9-7d7b14df55d7';
    const documentBody = {
      grakn_id: graknId,
      internal_id_key: internalIdKey,
      stix_id_key: stixId,
      name: 'Germany - Maze - October 2019',
      parent_types: ['Campaign', 'Stix-Domain-Entity', 'Stix-Domain']
    };
    const indexedData = await elIndex('test_index', documentBody);
    expect(indexedData).toEqual(documentBody);
    const documentWithIndex = assoc('_index', 'test_index', documentBody);
    // Load by internal Id
    const dataThroughInternal = await elLoadById(internalIdKey, null, null, ['test_index']);
    expect(dataThroughInternal).toEqual(documentWithIndex);
    // Load by stix id
    const dataThroughStix = await elLoadByStixId(stixId, 'Campaign', null, ['test_index']);
    expect(dataThroughStix).toEqual(documentWithIndex);
    // Load by grakn id
    const dataThroughGraknId = await elLoadByGraknId(graknId, 'Stix-Domain', null, ['test_index']);
    expect(dataThroughGraknId).toEqual(documentWithIndex);
  });
});

describe('Elasticsearch computation', () => {
  it('should count accurate', async () => {
    // const { endDate = null, type = null, types = null } = options;
    let malwaresCount = await elCount(INDEX_STIX_ENTITIES, { type: 'Malware' });
    expect(malwaresCount).toEqual(2);
    // Test with date filtering
    const mostRecentMalware = await elLoadByStixId('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    malwaresCount = await elCount(INDEX_STIX_ENTITIES, { type: 'Malware', endDate: mostRecentMalware.created_at });
    expect(malwaresCount).toEqual(1);
  });
  it('should aggregation accurate', async () => {
    // { "isRelation", "from", "to", "type", "value" }
    // "from", "to" is not use in elastic
    // Aggregate all stix domain by entity type, no filtering
    let malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      undefined, // No start
      undefined, // No end
      [] // No filters
    );
    let aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(2);
    expect(aggregationMap.get('marking-definition')).toEqual(5);
    // Aggregate with dates and simple filter
    const mostRecentMalware = await elLoadByStixId('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      '2019-01-01T00:00:00Z',
      new Date(mostRecentMalware.created_at).getTime() - 1,
      [{ type: 'name', value: 'Beacon' }] // No filters
    );
    aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.size).toEqual(1);
    expect(aggregationMap.get('malware')).toEqual(1);
    // Aggregate with relation filter
    const marking = await elLoadByStixId('marking-definition--f814dace-5888-4848-ab23-326518531d3e');
    malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      undefined, // No start
      undefined, // No end
      [{ isRelation: true, type: 'object_marking_refs', value: marking.internal_id_key }]
    );
    aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(2);
  });
});

describe('Elasticsearch pagination', () => {
  it('should paginate return correct data', async () => {
    // first = 200, after, types = null, filters = [], search = null,
    // orderBy = null, orderMode = 'asc',
    // relationsMap = null, forceNatural = false,
    // connectionFormat = true
    const data = await elPaginate(INDEX_STIX_ENTITIES, { types: ['Malware'] });
    expect(data).not.toBeNull();
    expect(data.edges.length).toBeGreaterThanOrEqual(2);
    const nodes = map(e => e.node, data.edges);
    const malware = find(propEq('stix_id_key', 'malware--c521e7de-aeb9-439b-8bb3-cd93a88f27ea'))(nodes);
    expect(malware.internal_id_key).not.toBeNull();
    expect(malware.name).toEqual('Beacon');
    expect(malware._index).toEqual(INDEX_STIX_ENTITIES);
    expect(malware.parent_types).toEqual(expect.arrayContaining(['Malware', 'Stix-Domain-Entity', 'Stix-Domain']));
  });
});
