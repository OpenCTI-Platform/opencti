/* eslint-disable no-underscore-dangle */
import { assoc, find, head, includes, map, propEq, uniq } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import moment from 'moment';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elCount,
  elCreateIndexes,
  elDeleteByField,
  elDeleteIndexes,
  elHistogramCount,
  elIndex,
  elIndexElements,
  elIndexExists,
  elIsAlive,
  elLoadByGraknId,
  elLoadById,
  elLoadByStixId,
  elLoadByTerms,
  elPaginate,
  elReconstructRelation,
  elVersion,
  forceNoCache,
  specialElasticCharsEscape,
} from '../../../src/database/elasticSearch';
import { INDEX_STIX_ENTITIES, INDEX_STIX_RELATIONS, utcDate } from '../../../src/database/utils';

describe('Elasticsearch configuration test', () => {
  it('should configuration correct', () => {
    expect(elIsAlive()).resolves.toBeTruthy();
    expect(elVersion()).resolves.toContain('7.6');
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
      parent_types: ['Campaign', 'Stix-Domain-Entity', 'Stix-Domain'],
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
    // Try to delete
    await elDeleteByField('test_index', 'internal_id_key', internalIdKey);
    const removedInternal = await elLoadById(internalIdKey, null, null, ['test_index']);
    expect(removedInternal).toBeNull();
  });
});

describe('Elasticsearch computation', () => {
  it('should count accurate', async () => {
    // const { endDate = null, type = null, types = null } = options;
    const malwaresCount = await elCount(INDEX_STIX_ENTITIES, { types: ['Malware'] });
    expect(malwaresCount).toEqual(2);
  });
  it('should count accurate with date filter', async () => {
    const mostRecentMalware = await elLoadByStixId('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const malwaresCount = await elCount(INDEX_STIX_ENTITIES, {
      types: ['Malware'],
      endDate: mostRecentMalware.created_at,
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
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('malware')).toEqual(2);
    expect(aggregationMap.get('marking-definition')).toEqual(6);
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
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.size).toEqual(1);
    expect(aggregationMap.get('malware')).toEqual(1);
  });
  it('should entity aggregation with relation accurate', async () => {
    // Aggregate with relation filter on marking definition TLP:RED
    const marking = await elLoadByStixId('marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27');
    const malwaresAggregation = await elAggregationCount(
      'Stix-Domain',
      'entity_type',
      undefined, // No start
      undefined, // No end
      [{ isRelation: true, type: 'object_marking_refs', value: marking.internal_id_key }]
    );
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
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
    const aggregationMap = new Map(reportRelationsAggregation.map((i) => [i.label, i.value]));
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
    const aggregationMap = new Map(intrusionRelationsAggregation.map((i) => [i.label, i.value]));
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
    // noinspection JSUnresolvedVariable
    const storedFormat = moment(head(data).date)._f;
    expect(storedFormat).toEqual('YYYY-MM-DD');
    expect(head(data).value).toEqual(24);
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
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019-08')).toEqual(undefined);
    expect(aggregationMap.get('2019-09')).toEqual(2);
    expect(aggregationMap.get('2019-10')).toEqual(1);
    expect(aggregationMap.get('2019-11')).toEqual(0);
    expect(aggregationMap.get('2019-12')).toEqual(0);
    expect(aggregationMap.get('2020-01')).toEqual(1);
    expect(aggregationMap.get('2020-02')).toEqual(12);
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
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(3);
    expect(aggregationMap.get('2020')).toEqual(14);
  });
  it('should year histogram with relation filter accurate', async () => {
    const data = await elHistogramCount(
      'Stix-Domain-Entity',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [{ isRelation: true, type: 'uses', value: '9f7f00f9-304b-4055-8c4f-f5eadb00de3b' }]
    );
    expect(data.length).toEqual(1);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(1);
  });
  it('should year histogram with relation filter accurate', async () => {
    const data = await elHistogramCount(
      'Stix-Domain-Entity',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [{ isRelation: true, type: undefined, value: '9f7f00f9-304b-4055-8c4f-f5eadb00de3b' }]
    );
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(1);
    expect(aggregationMap.get('2020')).toEqual(1);
  });
  it('should year histogram with attribute filter accurate', async () => {
    const data = await elHistogramCount(
      'Identity',
      'created',
      'year',
      undefined, // No start
      undefined, // No end
      [{ isRelation: false, type: 'name', value: 'The MITRE Corporation' }]
    );
    expect(data.length).toEqual(1);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2017')).toEqual(1);
  });
});

describe('Elasticsearch relation reconstruction', () => {
  const RELATION_ID = 'a0cfc7fc-837b-5ea0-b919-425047d4bb0d';
  const CONN_MALWARE_ID = '6fb84f02-f095-430e-87a0-394d41955eee';
  const CONN_MALWARE_GRAKN_ID = 'V454728';
  const CONN_MALWARE_ROLE = 'so';
  const CONN_MARKING_ID = '63309927-48f6-45c2-aee0-4d92b403cee5';
  const CONN_MARKING_GRAKN_ID = 'V409696';
  const CONN_MARKING_ROLE = 'marking';
  const buildRelationConcept = (relationType) => ({
    internal_id_key: RELATION_ID,
    entity_type: 'relation_embedded',
    relationship_type: relationType,
    connections: [
      {
        internal_id_key: CONN_MALWARE_ID,
        grakn_id: CONN_MALWARE_GRAKN_ID,
        role: CONN_MALWARE_ROLE,
        types: ['Malware', 'Stix-Domain-Entity', 'Stix-Domain'],
      },
      {
        internal_id_key: CONN_MARKING_ID,
        grakn_id: CONN_MARKING_GRAKN_ID,
        role: CONN_MARKING_ROLE,
        types: ['Marking-Definition', 'Stix-Domain'],
      },
    ],
  });
  it('Relation reconstruct natural', async () => {
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept);
    expect(relation.fromId).toEqual(CONN_MALWARE_GRAKN_ID);
    expect(relation.fromRole).toEqual(CONN_MALWARE_ROLE);
    expect(relation.toId).toEqual(CONN_MARKING_GRAKN_ID);
    expect(relation.toRole).toEqual(CONN_MARKING_ROLE);
  });
  it('Relation reconstruct with internal_id_key', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: undefined, role: undefined });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: CONN_MALWARE_ID, role: undefined });
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept, relationMap);
    expect(relation.internal_id_key).toEqual(concept.internal_id_key);
    expect(relation.fromId).toEqual(CONN_MALWARE_GRAKN_ID);
    expect(relation.fromInternalId).toEqual(CONN_MALWARE_ID);
    expect(relation.fromRole).toEqual(CONN_MALWARE_ROLE);
    expect(relation.toId).toEqual(CONN_MARKING_GRAKN_ID);
    expect(relation.toInternalId).toEqual(CONN_MARKING_ID);
    expect(relation.toRole).toEqual(CONN_MARKING_ROLE);
  });
  it('Relation reconstruct with no info', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: undefined, role: undefined });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: undefined, role: undefined });
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept, relationMap);
    expect(relation.fromId).toEqual(CONN_MALWARE_GRAKN_ID);
    expect(relation.toId).toEqual(CONN_MARKING_GRAKN_ID);
  });
  it('Relation reconstruct from reverse id', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: CONN_MALWARE_ID, role: undefined });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: undefined, role: undefined });
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept, relationMap);
    expect(relation.fromId).toEqual(CONN_MARKING_GRAKN_ID);
    expect(relation.toId).toEqual(CONN_MALWARE_GRAKN_ID);
  });
  it('Relation reconstruct from reverse id, forcing natural', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: CONN_MALWARE_ID, role: undefined });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: undefined, role: undefined });
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept, relationMap, true);
    expect(relation.fromId).toEqual(CONN_MALWARE_GRAKN_ID);
    expect(relation.toId).toEqual(CONN_MARKING_GRAKN_ID);
  });
  it('Relation reconstruct from roles', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: undefined, role: CONN_MALWARE_ROLE });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: undefined, role: CONN_MARKING_ROLE });
    const concept = buildRelationConcept('object_marking_refs');
    const relation = elReconstructRelation(concept, relationMap);
    expect(relation.fromId).toEqual(CONN_MARKING_GRAKN_ID);
    expect(relation.toId).toEqual(CONN_MALWARE_GRAKN_ID);
  });
  it('Relation reconstruct fail if no reverse definition', async () => {
    const concept = buildRelationConcept('undefined_relation');
    expect(() => {
      elReconstructRelation(concept, new Map());
    }).toThrow(Error);
  });
  it('Relation reconstruct fail with bad configuration', async () => {
    const relationMap = new Map();
    relationMap.set(CONN_MARKING_GRAKN_ID, { alias: 'to', internalIdKey: 'bad-to', role: undefined });
    relationMap.set(CONN_MALWARE_GRAKN_ID, { alias: 'from', internalIdKey: undefined, role: undefined });
    const concept = buildRelationConcept('object_marking_refs');
    expect(() => {
      elReconstructRelation(concept, relationMap);
    }).toThrow(Error);
  });
});

describe('Elasticsearch pagination', () => {
  it('Pagination standard escape', async () => {
    // +|\-*()~={}:?\\
    let escape = specialElasticCharsEscape('Looking {for} [malware] : ~APT');
    expect(escape).toEqual('Looking \\{for\\} \\[malware\\] \\: \\~APT');
    escape = specialElasticCharsEscape('Looking (threat) = ?maybe');
    expect(escape).toEqual('Looking \\(threat\\) \\= \\?maybe');
    escape = specialElasticCharsEscape('Looking All* + Everything| - \\with');
    expect(escape).toEqual('Looking All\\* \\+ Everything\\| \\- \\\\with');
  });
  it('should entity paginate everything', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES);
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(64);
    const filterBaseTypes = uniq(map((e) => e.node.base_type, data.edges));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('entity');
  });
  it('should entity search with trailing slash', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'groups/G0096' });
    expect(data).not.toBeNull();
    // external-reference--d1b50d16-2c9c-45f2-8ae0-d5b554e0fbf5 | url
    // intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7 | description
    expect(data.edges.length).toEqual(2);
  });
  it('should entity paginate everything after', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES, { after: offsetToCursor(30) });
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(34);
  });
  it('should entity paginate with single type', async () => {
    // first = 200, after, types = null, filters = [], search = null,
    // orderBy = null, orderMode = 'asc',
    // relationsMap = null, forceNatural = false,
    // connectionFormat = true
    const data = await elPaginate(INDEX_STIX_ENTITIES, { types: ['Malware'] });
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(2);
    const nodes = map((e) => e.node, data.edges);
    const malware = find(propEq('stix_id_key', 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c'))(nodes);
    expect(malware.internal_id_key).not.toBeNull();
    expect(malware.name).toEqual('Paradise Ransomware');
    expect(malware._index).toEqual(INDEX_STIX_ENTITIES);
    expect(malware.parent_types).toEqual(expect.arrayContaining(['Malware', 'Stix-Domain-Entity', 'Stix-Domain']));
  });
  it('should entity paginate with classic search', async () => {
    let data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'malicious' });
    expect(data.edges.length).toEqual(2);
    data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'with malicious' });
    expect(data.edges.length).toEqual(5);
    data = await elPaginate(INDEX_STIX_ENTITIES, { search: '"with malicious"' });
    expect(data.edges.length).toEqual(1);
  });
  it('should entity paginate with escaped search', async () => {
    let data = await elPaginate(INDEX_STIX_ENTITIES, { search: '(Citation:' });
    expect(data.edges.length).toEqual(3);
    data = await elPaginate(INDEX_STIX_ENTITIES, { search: '[APT41]' });
    expect(data.edges.length).toEqual(1);
    data = await elPaginate(INDEX_STIX_ENTITIES, { search: '%5BAPT41%5D' });
    expect(data.edges.length).toEqual(1);
  });
  it('should entity paginate with http and https', async () => {
    let data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'http://attack.mitre.org/groups/G0096' });
    expect(data.edges.length).toEqual(2);
    data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'https://attack.mitre.org/groups/G0096' });
    expect(data.edges.length).toEqual(2);
  });
  it('should entity paginate with incorrect encoding', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES, { search: 'ATT%' });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with field not exist filter', async () => {
    const filters = [{ key: 'color', operator: undefined, values: [null] }];
    const data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(57); // The 4 Default TLP Marking definitions + 1
  });
  it('should entity paginate with field exist filter', async () => {
    const filters = [{ key: 'color', operator: undefined, values: ['EXISTS'] }];
    const data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(7); // The 4 Default TLP Marking definitions
  });
  it('should entity paginate with equality filter', async () => {
    // eq operation will use the field.keyword to do an exact field equality
    let filters = [{ key: 'color', operator: 'eq', values: ['#c62828'] }];
    let data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(1);
    // Special case when operator = eq + the field key is a dateFields => use a match
    filters = [{ key: 'published', operator: 'eq', values: ['2020-03-01'] }];
    data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(1);
  });
  it('should entity paginate with match filter', async () => {
    let filters = [{ key: 'entity_type', operator: 'match', values: ['marking'] }];
    let data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(6); // The 4 Default TLP + MITRE Corporation
    // Verify that nothing is found in this case if using the eq operator
    filters = [{ key: 'entity_type', operator: 'eq', values: ['marking'] }];
    data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with dates filter', async () => {
    let filters = [{ key: 'created', operator: 'lte', values: ['2017-06-01T00:00:00.000Z'] }];
    let data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(2); // The 4 Default TLP + MITRE Corporation
    filters = [
      { key: 'created', operator: 'gt', values: ['2020-03-01T14:06:06.255Z'] },
      { key: 'color', operator: undefined, values: [null] },
    ];
    data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(3);
    filters = [
      { key: 'created', operator: 'lte', values: ['2017-06-01T00:00:00.000Z'] },
      { key: 'created', operator: 'gt', values: ['2020-03-01T14:06:06.255Z'] },
    ];
    data = await elPaginate(INDEX_STIX_ENTITIES, { filters });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with date ordering', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES, { orderBy: 'created', orderMode: 'asc' });
    expect(data.edges.length).toEqual(39);
    const createdDates = map((e) => e.node.created, data.edges);
    let previousCreatedDate = null;
    for (let index = 0; index < createdDates.length; index += 1) {
      const createdDate = createdDates[index];
      if (!previousCreatedDate) {
        previousCreatedDate = createdDate;
      } else {
        const previousMoment = utcDate(previousCreatedDate);
        const currentMoment = utcDate(createdDate);
        expect(previousMoment.isValid()).toBeTruthy();
        expect(currentMoment.isValid()).toBeTruthy();
        expect(previousMoment.isSameOrBefore(currentMoment)).toBeTruthy();
      }
    }
  });
  it('should entity paginate with keyword ordering', async () => {
    const filters = [{ key: 'color', operator: undefined, values: ['EXISTS'] }];
    const data = await elPaginate(INDEX_STIX_ENTITIES, { filters, orderBy: 'definition', orderMode: 'desc' });
    expect(data.edges.length).toEqual(4);
    const markings = map((e) => e.node.definition, data.edges);
    expect(markings[0]).toEqual('TLP:WHITE');
    expect(markings[1]).toEqual('TLP:RED');
    expect(markings[2]).toEqual('TLP:GREEN');
    expect(markings[3]).toEqual('TLP:AMBER');
  });
  it('should relation paginate everything', async () => {
    let data = await elPaginate(INDEX_STIX_RELATIONS);
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(103);
    let filterBaseTypes = uniq(map((e) => e.node.base_type, data.edges));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('relation');
    // Same query with no pagination
    data = await elPaginate(INDEX_STIX_RELATIONS, { connectionFormat: false });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(103);
    filterBaseTypes = uniq(map((e) => e.base_type, data));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('relation');
  });
});

describe('Elasticsearch basic loader', () => {
  it('should entity load by internal id', async () => {
    const data = await elLoadById('ab78a62f-4928-4d5a-8740-03f0af9c4330', 'Stix-Domain-Entity');
    expect(data).not.toBeNull();
    expect(data.stix_id_key).toEqual('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(data.revoked).toBeFalsy();
    expect(data.name).toEqual('Paradise Ransomware');
    expect(data.entity_type).toEqual('malware');
  });
  it('should entity load by stix id', async () => {
    const data = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c', 'Stix-Domain');
    expect(data).not.toBeNull();
    expect(data.id).toEqual('ab78a62f-4928-4d5a-8740-03f0af9c4330');
    expect(data.revoked).toBeFalsy();
    expect(data.name).toEqual('Paradise Ransomware');
    expect(data.entity_type).toEqual('malware');
  });
  it('should entity load by grakn id', async () => {
    const finder = await elLoadByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c', 'Malware');
    const data = await elLoadByGraknId(finder.grakn_id, 'malware');
    expect(data).not.toBeNull();
    expect(data.grakn_id).toEqual(finder.grakn_id);
    expect(data.revoked).toBeFalsy();
    expect(data.name).toEqual('Paradise Ransomware');
    expect(data.entity_type).toEqual('malware');
  });
  it('should relation reconstruct', async () => {
    const data = await elLoadByStixId('relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9');
    expect(data).not.toBeNull();
    expect(data.fromRole).toEqual('indicator');
    expect(data.toRole).toEqual('characterize');
    expect(data.entity_type).toEqual('stix_relation');
  });
  it('should relation creation use x_opencti_id', async () => {
    const data = await elLoadByStixId('relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02');
    expect(data).not.toBeNull();
    expect(data.id).toEqual('209cbdf0-fc5e-47c9-8023-dd724993ae55');
  });
});

describe('Elasticsearch reindex', () => {
  const malwareInternalId = 'ab78a62f-4928-4d5a-8740-03f0af9c4330';
  const attackId = 'dcbadcd2-9359-48ac-8b86-88e38a092a2b';
  const checkRelationConnections = async () => {
    let terms = [{ 'internal_id_key.keyword': malwareInternalId }, { 'rel_uses.internal_id_key.keyword': attackId }];
    const malware = await elLoadByTerms(terms);
    expect(malware).not.toBeNull();
    terms = [{ 'internal_id_key.keyword': attackId }, { 'rel_uses.internal_id_key.keyword': malwareInternalId }];
    const attack = await elLoadByTerms(terms);
    expect(attack).not.toBeNull();
  };
  it('should relation correctly indexed', async () => {
    // relationship_type -> uses
    // source_ref -> malware--faa5b705-cf44-4e50-8472-29e5fec43c3c
    // target_ref -> attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
    const data = await elLoadByStixId('relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de', 'stix_relation');
    expect(data).not.toBeNull();
    expect(data.connections.length).toEqual(2);
    const connections = map((c) => c.internal_id_key, data.connections);
    expect(includes(malwareInternalId, connections)).toBeTruthy(); // malware--faa5b705-cf44-4e50-8472-29e5fec43c3c
    expect(includes(attackId, connections)).toBeTruthy(); // attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
    // Malware must be find by the relation
    await checkRelationConnections();
  });
  it('should relation reindex check consistency', async () => {
    const indexPromise = elIndexElements([{ relationship_type: 'uses' }]);
    // noinspection ES6MissingAwait
    expect(indexPromise).rejects.toThrow();
  });
});
