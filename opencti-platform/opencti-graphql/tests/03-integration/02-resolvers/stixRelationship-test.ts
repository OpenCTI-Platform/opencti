import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { stixRelationshipsDistribution, stixRelationshipsNumber } from '../../../src/domain/stixRelationship';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { ABSTRACT_STIX_RELATIONSHIP } from '../../../src/schema/general';
import { LABEL_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { RELATION_INDICATES, RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../../src/schema/stixRefRelationship';
import { UNTIL_END_STR } from '../../../src/utils/format';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import { relationsCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';

describe('StixRelationship', () => {
  it('should limit stixRelationshipsDistribution scope to stix relationships', async () => {
    const args = {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      relationship_type: [RELATION_PARTICIPATE_TO],
    };
    await expect(() => stixRelationshipsDistribution(testContext, ADMIN_USER, args)).rejects.toThrowError('relationship_type is not a stix-relationship');
  });
  it('should stixRelationship number with object ref relationship', async () => {
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: ['object'],
          operator: 'eq',
          mode: 'or',
        },
        {
          key: 'toTypes',
          values: [ENTITY_TYPE_ATTACK_PATTERN],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(5); // 2 attack patterns are contained in report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7
  });
  it('should stixRelationship number with object and malware', async () => {
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [RELATION_OBJECT],
          operator: 'eq',
          mode: 'or',
        },
        {
          key: 'toTypes',
          values: [ENTITY_TYPE_MALWARE],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(28);
    // 1 malware contained in report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7
    // + 1 in note--573f623c-bf68-4f19-9500-d618f0d00af0
    // + 1 in opinion--fab0d63d-e1be-4771-9c14-043b76f71d4f
    // + 1 in observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be
  });
  it('should stixRelationship number with sighting', async () => {
    // -- stix sighting relationships --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [STIX_SIGHTING_RELATIONSHIP],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(relationsCounter['stix-sighting-relationship']); // number of stix-sighting-relationships
  });
  it('should stixRelationship number with indicates and related-to', async () => {
    // -- stix core relationships --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [RELATION_RELATED_TO, RELATION_INDICATES],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(relationsCounter['related-to'] + relationsCounter.indicates + 55); // 2 'related-to' relationships + 4 'indicates' relationships
  });
  it('should stixRelationship number with labels', async () => {
    // -- 'label' ref relationship (not taken into account) --
    const relationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [LABEL_FILTER],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const relationshipsNumber = await relationshipsNumberResult.count;
    expect(relationshipsNumber).toEqual(0); // ref relationships are not taken into account in stixRelationshipsNumber (except the 'object' ref)
  });
  it('should stixRelationship number with all', async () => {
    // -- all relationships --
    const allRelationshipsNumberResult = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
    });
    const allRelationshipsNumberResult2 = await stixRelationshipsNumber(testContext, ADMIN_USER, {
      dateAttribute: 'created_at',
      endDate: UNTIL_END_STR,
      filters: {
        mode: 'and',
        filters: [{
          key: 'relationship_type',
          values: [ABSTRACT_STIX_RELATIONSHIP],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    });
    const allRelationshipsNumber = await allRelationshipsNumberResult.count;
    const allRelationshipsNumber2 = await allRelationshipsNumberResult2.count;
    expect(allRelationshipsNumber).toEqual(allRelationshipsNumber2); // the relationships taken into account are : stix core, sightings, the 'object' ref
  });
});

describe('stixRelationshipsTimeSeriesBreakdown', () => {
  const ORGANIZATION_ADD_QUERY = gql`
    mutation OrganizationAdd($input: OrganizationAddInput!) {
      organizationAdd(input: $input) {
        id
      }
    }
  `;
  const ORGANIZATION_DELETE_QUERY = gql`
    mutation OrganizationDelete($id: ID!) {
      organizationDelete(id: $id)
    }
  `;
  const MALWARE_ADD_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
      malwareAdd(input: $input) {
        id
      }
    }
  `;
  const MALWARE_DELETE_QUERY = gql`
    mutation MalwareDelete($id: ID!) {
      malwareEdit(id: $id) {
        delete
      }
    }
  `;
  const INTRUSION_SET_ADD_QUERY = gql`
    mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
      intrusionSetAdd(input: $input) {
        id
      }
    }
  `;
  const INTRUSION_SET_DELETE_QUERY = gql`
    mutation IntrusionSetDelete($id: ID!) {
      intrusionSetEdit(id: $id) {
        delete
      }
    }
  `;
  const RELATIONSHIP_ADD_QUERY = gql`
    mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
      stixCoreRelationshipAdd(input: $input) {
        id
      }
    }
  `;
  const RELATIONSHIP_DELETE_QUERY = gql`
    mutation StixCoreRelationshipDelete($id: ID!) {
      stixCoreRelationshipEdit(id: $id) {
        delete
      }
    }
  `;
  const BREAKDOWN_QUERY = gql`
    query StixRelationshipsTimeSeriesBreakdown(
      $field: String!
      $dateAttribute: String
      $startDate: DateTime!
      $endDate: DateTime
      $interval: String!
      $limit: Int
      $order: OrderingMode
      $includeOther: Boolean
      $relationship_type: [String!]
      $filters: FilterGroup
      $dynamicFrom: FilterGroup
      $dynamicTo: FilterGroup
    ) {
      stixRelationshipsTimeSeriesBreakdown(
        field: $field
        dateAttribute: $dateAttribute
        startDate: $startDate
        endDate: $endDate
        interval: $interval
        limit: $limit
        order: $order
        includeOther: $includeOther
        relationship_type: $relationship_type
        filters: $filters
        dynamicFrom: $dynamicFrom
        dynamicTo: $dynamicTo
      ) {
        truncated
        dates
        series {
          label
          value
          isOther
          entity {
            ... on MarkingDefinition {
              definition
            }
          }
          values
        }
      }
    }
  `;
  const TIME_SERIES_QUERY = gql`
    query StixRelationshipsMultiTimeSeries(
      $startDate: DateTime!
      $endDate: DateTime
      $interval: String!
      $timeSeriesParameters: [StixRelationshipsTimeSeriesParameters]
    ) {
      stixRelationshipsMultiTimeSeries(
        operation: count
        startDate: $startDate
        endDate: $endDate
        interval: $interval
        timeSeriesParameters: $timeSeriesParameters
      ) {
        data {
          date
          value
        }
      }
    }
  `;
  type Serie = { label: string; value: number; isOther: boolean; entity: { definition: string } | null; values: number[] };
  // Relationships (creation date, source, type, target, marking) over January to March 2021:
  // targets 3 and uses 2; from 2 malwares and 3 intrusion sets; to 3 organizations and 2 malwares; 3 green, 1 amber, 1 without marking.
  // A user of the green group reads all of them but the amber one: from January to March 2, 1 and 1 relationships.
  const RELATIONSHIPS: { created: string; from: string; relationship_type: string; to: string; marking: string | null }[] = [
    { created: '2021-01-10T12:00:00.000Z', from: 'malwareA', relationship_type: 'targets', to: 'organization', marking: MARKING_TLP_GREEN },
    { created: '2021-01-20T12:00:00.000Z', from: 'malwareB', relationship_type: 'targets', to: 'organization', marking: MARKING_TLP_GREEN },
    { created: '2021-02-10T12:00:00.000Z', from: 'intrusionSet', relationship_type: 'targets', to: 'organization', marking: MARKING_TLP_AMBER },
    { created: '2021-02-20T12:00:00.000Z', from: 'intrusionSet', relationship_type: 'uses', to: 'malwareA', marking: MARKING_TLP_GREEN },
    { created: '2021-03-10T12:00:00.000Z', from: 'intrusionSet', relationship_type: 'uses', to: 'malwareB', marking: null },
  ];
  const ids: Record<string, string> = {};
  const relationshipIds: string[] = [];
  const period = { startDate: '2021-01-01T00:00:00.000Z', endDate: '2021-03-31T23:59:59.999Z', interval: 'month' };
  // Isolate the relationships of this test from the ones of the other tests
  const authorFilter = () => ({ mode: 'and', filters: [{ key: ['createdBy'], values: [ids.organization] }], filterGroups: [] });
  const intrusionSets = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Intrusion-Set'], operator: 'eq', mode: 'or' }], filterGroups: [] };
  const malwares = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };

  type Breakdown = { truncated: boolean; dates: (Date | string)[]; series: Serie[] };
  const breakdownRequest = (variables: Record<string, unknown>) => ({
    query: BREAKDOWN_QUERY,
    variables: { ...period, dateAttribute: 'created', filters: authorFilter(), ...variables },
  });
  const breakdown = async (variables: Record<string, unknown>) => {
    const result = await queryAsAdminWithSuccess(breakdownRequest(variables));
    return result.data?.stixRelationshipsTimeSeriesBreakdown as Breakdown;
  };
  // As a user of the green group, who does not read the amber relationship
  const breakdownAsGreenUser = async (variables: Record<string, unknown>) => {
    const result = await queryAsUserWithSuccess(USER_PARTICIPATE, breakdownRequest(variables));
    return result.data?.stixRelationshipsTimeSeriesBreakdown as Breakdown;
  };
  const timeSeriesRequest = (parameters: Record<string, unknown>) => ({
    query: TIME_SERIES_QUERY,
    variables: { ...period, timeSeriesParameters: [{ field: 'created', filters: authorFilter(), ...parameters }] },
  });
  const valuesOf = (data: Record<string, any> | undefined) => (data?.stixRelationshipsMultiTimeSeries[0].data as { value: number }[]).map(({ value }) => value);
  const timeSeries = async (parameters: Record<string, unknown> = {}) => valuesOf((await queryAsAdminWithSuccess(timeSeriesRequest(parameters))).data);
  const timeSeriesAsGreenUser = async () => valuesOf((await queryAsUserWithSuccess(USER_PARTICIPATE, timeSeriesRequest({}))).data);
  const summary = (series: Serie[]) => series.map((serie) => [serie.label, serie.value, serie.values]);
  const expectBreakdownError = (variables: Record<string, unknown>, message: string) => {
    const request = { query: BREAKDOWN_QUERY, variables: { ...period, dateAttribute: 'created', ...variables } };
    return queryAsAdminWithError(request, message, 'FUNCTIONAL_ERROR');
  };

  beforeAll(async () => {
    const organization = await queryAsAdminWithSuccess({ query: ORGANIZATION_ADD_QUERY, variables: { input: { name: 'bkd-rel-author' } } });
    ids.organization = organization.data?.organizationAdd.id;
    for (const key of ['malwareA', 'malwareB']) {
      const malware = await queryAsAdminWithSuccess({ query: MALWARE_ADD_QUERY, variables: { input: { name: `bkd-rel-${key}` } } });
      ids[key] = malware.data?.malwareAdd.id;
    }
    const intrusionSet = await queryAsAdminWithSuccess({ query: INTRUSION_SET_ADD_QUERY, variables: { input: { name: 'bkd-rel-intrusion-set' } } });
    ids.intrusionSet = intrusionSet.data?.intrusionSetAdd.id;
    for (let i = 0; i < RELATIONSHIPS.length; i += 1) {
      const { created, from, relationship_type, to, marking } = RELATIONSHIPS[i];
      const relationship = await queryAsAdminWithSuccess({
        query: RELATIONSHIP_ADD_QUERY,
        variables: {
          input: {
            relationship_type,
            fromId: ids[from],
            toId: ids[to],
            created,
            createdBy: ids.organization,
            objectMarking: marking ? [marking] : [],
          },
        },
      });
      relationshipIds.push(relationship.data?.stixCoreRelationshipAdd.id);
    }
  });

  afterAll(async () => {
    for (let i = 0; i < relationshipIds.length; i += 1) {
      await queryAsAdminWithSuccess({ query: RELATIONSHIP_DELETE_QUERY, variables: { id: relationshipIds[i] } });
    }
    for (const key of ['malwareA', 'malwareB']) {
      if (ids[key]) await queryAsAdminWithSuccess({ query: MALWARE_DELETE_QUERY, variables: { id: ids[key] } });
    }
    if (ids.intrusionSet) {
      await queryAsAdminWithSuccess({ query: INTRUSION_SET_DELETE_QUERY, variables: { id: ids.intrusionSet } });
    }
    if (ids.organization) {
      await queryAsAdminWithSuccess({ query: ORGANIZATION_DELETE_QUERY, variables: { id: ids.organization } });
    }
  });

  it('should break down by relationship type', async () => {
    const { truncated, dates, series } = await breakdown({ field: 'relationship_type' });
    expect(truncated).toEqual(false);
    expect(dates.map((date) => new Date(date).toISOString())).toEqual(['2021-01-01T00:00:00.000Z', '2021-02-01T00:00:00.000Z', '2021-03-01T00:00:00.000Z']);
    expect(summary(series)).toEqual([['targets', 3, [2, 1, 0]], ['uses', 2, [0, 1, 1]]]);
    expect(series.every((serie) => serie.entity === null && !serie.isOther)).toEqual(true);
  });

  it('should break down by the type of the source or of the target', async () => {
    const bySource = await breakdown({ field: 'fromTypes' });
    expect(summary(bySource.series)).toEqual([['Intrusion-Set', 3, [0, 2, 1]], ['Malware', 2, [2, 0, 0]]]);
    const byTarget = await breakdown({ field: 'toTypes' });
    expect(summary(byTarget.series)).toEqual([['Organization', 3, [2, 1, 0]], ['Malware', 2, [0, 1, 1]]]);
    // The lowest first, the other types in the Other serie
    const lowest = await breakdown({ field: 'toTypes', order: 'asc', limit: 1, includeOther: true });
    expect(lowest.truncated).toEqual(true);
    expect(summary(lowest.series)).toEqual([['Malware', 2, [0, 1, 1]], ['Other', 3, [2, 1, 0]]]);
    expect(lowest.series.map((serie) => serie.isOther)).toEqual([false, true]);
  });

  it('should break down by marking, the relationships without marking in the Other serie', async () => {
    const { truncated, series } = await breakdown({ field: 'objectMarking', limit: 1, includeOther: true });
    expect(truncated).toEqual(true);
    expect(series.map((serie) => serie.entity?.definition ?? serie.label)).toEqual(['TLP:GREEN', 'Other']);
    expect(series.map((serie) => [serie.value, serie.values])).toEqual([[3, [2, 1, 0]], [2, [0, 1, 1]]]);
  });

  it('should restrict the relationships with the dynamic source and target, as the relationships time series', async () => {
    const fromIntrusionSets = await breakdown({ field: 'relationship_type', dynamicFrom: intrusionSets });
    expect(summary(fromIntrusionSets.series)).toEqual([['uses', 2, [0, 1, 1]], ['targets', 1, [0, 1, 0]]]);
    const toMalwares = await breakdown({ field: 'fromTypes', dynamicTo: malwares });
    expect(summary(toMalwares.series)).toEqual([['Intrusion-Set', 2, [0, 1, 1]]]);
    // A breakdown with its Other serie splits the relationships time series of the same dataset
    for (const dataset of [{}, { dynamicFrom: intrusionSets }, { dynamicTo: malwares }]) {
      const total = await timeSeries(dataset);
      for (const field of ['relationship_type', 'fromTypes', 'toTypes', 'objectMarking']) {
        const { series } = await breakdown({ field, includeOther: true, ...dataset });
        const sums = total.map((_, index) => series.reduce((sum, serie) => sum + serie.values[index], 0));
        expect(sums, `${field} of ${JSON.stringify(dataset)}`).toEqual(total);
      }
    }
  });

  it('should not count the relationships above the markings of the user, neither in the series nor in Other', async () => {
    // The amber marking is not a value for the user, and Other only counts the relationship without marking (March):
    // [0, 1, 1] for the admin, the amber relationship of February included
    const byMarking = await breakdownAsGreenUser({ field: 'objectMarking', limit: 10, includeOther: true });
    expect(byMarking.truncated).toEqual(false);
    expect(byMarking.series.map((serie) => [serie.entity?.definition ?? serie.label, serie.value, serie.values])).toEqual([
      ['TLP:GREEN', 3, [2, 1, 0]],
      ['Other', 1, [0, 0, 1]],
    ]);
    // targets loses the amber relationship of February: targets and uses then tie, so the series are compared by label
    const byType = await breakdownAsGreenUser({ field: 'relationship_type', includeOther: true });
    expect(Object.fromEntries(byType.series.map((serie) => [serie.label, [serie.value, serie.values]]))).toEqual({
      targets: [2, [2, 0, 0]],
      uses: [2, [0, 1, 1]],
      Other: [0, [0, 0, 0]],
    });
    // A breakdown with its Other serie splits the relationships time series of the user, whatever the field
    const total = await timeSeriesAsGreenUser();
    expect(total).toEqual([2, 1, 1]);
    for (const field of ['relationship_type', 'fromTypes', 'toTypes', 'objectMarking']) {
      const { series } = await breakdownAsGreenUser({ field, includeOther: true });
      const sums = total.map((_, index) => series.reduce((sum, serie) => sum + serie.values[index], 0));
      expect(sums, field).toEqual(total);
    }
  });

  it('should check the field against the requested relationship types', async () => {
    const targets = await breakdown({ field: 'toTypes', relationship_type: ['targets'] });
    expect(summary(targets.series)).toEqual([['Organization', 3, [2, 1, 0]]]);
  });

  it('should refuse a field that cannot be broken down', async () => {
    const message = 'Time series breakdown does not support this field for these relationship types';
    for (const field of ['fromId', 'toId', 'objects', 'externalReferences', 'entity_type', 'description']) {
      await expectBreakdownError({ field }, message);
    }
  });

  it('should refuse an invalid limit or interval', async () => {
    const message = 'Time series breakdown limit must be an integer between 1 and the maximum';
    await expectBreakdownError({ field: 'relationship_type', limit: 0 }, message);
    await expectBreakdownError({ field: 'relationship_type', limit: 51 }, message);
    await expectBreakdownError({ field: 'relationship_type', interval: 'minute' }, 'Unsupported interval, please choose between year, quarter, month, week, day or hour');
  });
});
