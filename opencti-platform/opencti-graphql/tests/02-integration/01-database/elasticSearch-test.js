/* eslint-disable no-underscore-dangle */
import { assoc, find, propEq, map, head } from 'ramda';
import moment from 'moment';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elCount,
  elCreateIndexes,
  elDeleteIndexes,
  elHistogramCount,
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
    const malwaresCount = await elCount(INDEX_STIX_ENTITIES, { type: 'Malware' });
    expect(malwaresCount).toEqual(2);
  });
  it('should count accurate with date filter', async () => {
    const mostRecentMalware = await elLoadByStixId('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const malwaresCount = await elCount(INDEX_STIX_ENTITIES, {
      type: 'Malware',
      endDate: mostRecentMalware.created_at
    });
    expect(malwaresCount).toEqual(1);
  });
  it('should entity aggregation accurate', async () => {
    // { "isRelation", "from", "to", "type", "value" }
    // "from", "to" is not use in elastic
    // Aggregate all stix domain by entity type, no filtering
    const malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      undefined, // No start
      undefined, // No end
      [] // No filters
    );
    const aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(2);
    expect(aggregationMap.get('marking-definition')).toEqual(5);
  });
  it('should entity aggregation with date accurate', async () => {
    const mostRecentMalware = await elLoadByStixId('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      '2019-01-01T00:00:00Z',
      new Date(mostRecentMalware.created_at).getTime() - 1,
      [{ type: 'name', value: 'Paradise Ransomware' }] // Filter on name
    );
    const aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.size).toEqual(1);
    expect(aggregationMap.get('malware')).toEqual(1);
  });
  it('should entity aggregation with relation accurate', async () => {
    // Aggregate with relation filter on marking definition TLP:TEST
    const marking = await elLoadByStixId('marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed');
    const malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      undefined, // No start
      undefined, // No end
      [{ isRelation: true, type: 'object_marking_refs', value: marking.internal_id_key }]
    );
    const aggregationMap = new Map(malwaresAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(1);
    expect(aggregationMap.get('report')).toEqual(1);
  });
  it('should relation aggregation accurate', async () => {
    const testingReport = await elLoadByStixId('report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const reportRelationsAggregation = await elAggregationRelationsCount(
      'stix_relation_embedded',
      null,
      null,
      ['Stix-Domain'], //
      testingReport.internal_id_key
    );
    const aggregationMap = new Map(reportRelationsAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('indicator')).toEqual(3);
    expect(aggregationMap.get('organization')).toEqual(3);
    expect(aggregationMap.get('attack-pattern')).toEqual(2);
    expect(aggregationMap.get('city')).toEqual(1);
    expect(aggregationMap.get('country')).toEqual(1);
    expect(aggregationMap.get('intrusion-set')).toEqual(1);
    expect(aggregationMap.get('malware')).toEqual(1);
    expect(aggregationMap.get('marking-definition')).toEqual(1);
    expect(aggregationMap.get('sector')).toEqual(1);
  });
  it('should relation aggregation with date accurate', async () => {
    const intrusionSet = await elLoadByStixId('intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const intrusionRelationsAggregation = await elAggregationRelationsCount(
      'stix_relation',
      '2020-02-29T00:00:00Z',
      new Date().getTime(),
      ['Stix-Domain'], //
      intrusionSet.internal_id_key
    );
    const aggregationMap = new Map(intrusionRelationsAggregation.map(i => [i.label, i.value]));
    expect(aggregationMap.get('city')).toEqual(1);
    expect(aggregationMap.get('indicator')).toEqual(1);
    expect(aggregationMap.get('organization')).toEqual(1);
    expect(aggregationMap.get('malware')).toEqual(undefined); // Because of date filtering
  });
  it('should invalid time histogram fail', async () => {
    const histogramCount = elHistogramCount('Stix-Domain-Entity', 'created_at', 'minute', null, null, []);
    // noinspection ES6MissingAwait
    expect(histogramCount).rejects.toThrow();
  });
  it('should day histogram accurate', async () => {
    const data = await elHistogramCount(
      'Stix-Domain-Entity',
      'created_at',
      'day',
      '2019-09-29T00:00:00.000Z',
      new Date().getTime(),
      []
    );
    expect(data.length).toEqual(1);
    // eslint-disable-next-line prettier/prettier
    const nowDate = moment().utc().format('YYYY-MM-DD');
    expect(head(data).date).toEqual(nowDate);
    expect(head(data).value).toEqual(18);
  });
  it('should month histogram accurate', async () => {
    const data = await elHistogramCount(
      'Stix-Domain-Entity',
      'created',
      'month',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      []
    );
    expect(data.length).toEqual(7);
    const aggregationMap = new Map(data.map(i => [i.date, i.value]));
    expect(aggregationMap.get('2019-08')).toEqual(undefined);
    expect(aggregationMap.get('2019-09')).toEqual(2);
    expect(aggregationMap.get('2019-10')).toEqual(1);
    expect(aggregationMap.get('2019-11')).toEqual(0);
    expect(aggregationMap.get('2019-12')).toEqual(0);
    expect(aggregationMap.get('2020-01')).toEqual(1);
    expect(aggregationMap.get('2020-02')).toEqual(9);
    expect(aggregationMap.get('2020-03')).toEqual(1);
  });
  it('should year histogram accurate', async () => {
    const data = await elHistogramCount(
      'Stix-Domain-Entity',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      []
    );
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map(i => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(3);
    expect(aggregationMap.get('2020')).toEqual(11);
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
    const malware = find(propEq('stix_id_key', 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c'))(nodes);
    expect(malware.internal_id_key).not.toBeNull();
    expect(malware.name).toEqual('Paradise Ransomware');
    expect(malware._index).toEqual(INDEX_STIX_ENTITIES);
    expect(malware.parent_types).toEqual(expect.arrayContaining(['Malware', 'Stix-Domain-Entity', 'Stix-Domain']));
  });
});
