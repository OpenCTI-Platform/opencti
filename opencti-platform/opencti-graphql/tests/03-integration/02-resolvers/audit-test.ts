import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  awaitUntilCondition,
  queryAsAdminWithError,
  queryAsAdminWithSuccess,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
  queryUnauthenticatedIsExpectedForbidden,
} from '../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_PARTICIPATE, USER_PLATFORM_ADMIN, USER_SECURITY } from '../../utils/testQuery';
import { addReport } from '../../../src/domain/report';
import { stixDomainObjectDelete, stixDomainObjectEditField } from '../../../src/domain/stixDomainObject';
import { utcDate } from '../../../src/utils/format';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

const AUDIT_QUERY = gql`
    query AuditQuery(
        $search: String
        $types: [String!]
        $first: Int!
        $orderBy: LogsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        audits(
            search: $search
            types: $types
            first: $first
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) {
            edges {
                node {
                    id
                    entity_type
                    event_type
                    event_scope
                    event_status
                    timestamp
                    context_uri
                    user {
                        id
                        name
                    }
                    context_data {
                        entity_id
                        entity_type
                        entity_name
                        message
                    }
                }
            }
        }
    }
`;
const AUDITS_DISTRIBUTION_QUERY = gql`
    query AuditsDistributionQuery(
        $field: String!
        $operation: StatsOperation!
        $types: [String]
        $filters: FilterGroup
        $limit: Int
    ) {
        auditsDistribution(
            field: $field
            operation: $operation
            types: $types
            filters: $filters
            limit: $limit
        ) {
            label
            value
            entity {
                ... on BasicObject {
                    id
                    entity_type
                }
                ... on StixObject {
                  representative {
                    main
                  }
                }
                ... on InternalObject {
                    representative {
                        main
                    }
                }
            }
        }
    }
`;

describe('audits query', () => {
  it('should Participant user not be allowed to request audit data.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10,
      },
    });
  });

  it('should Security user be allowed to request audit data.', async () => {
    await queryAsUserWithSuccess(USER_SECURITY, {
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10,
      },
    });
  });

  it('Should user cannot access audit and knowledge data if not authenticated', async () => {
    await queryUnauthenticatedIsExpectedForbidden({
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10,
      },
    });
  });

  it('should search Activity logs on startup-generated events', async () => {
    let foundEdges: Array<{ node: { entity_type: string } }> = [];
    let searchTerm: string | undefined;

    await awaitUntilCondition(async () => {
      const initialResult = await queryAsAdminWithSuccess({
        query: AUDIT_QUERY,
        variables: {
          types: ['Activity'],
          first: 25,
        },
      });
      const initialEdges = initialResult.data.audits.edges;
      if (initialEdges.length === 0) {
        return false;
      }

      const firstActivity = initialEdges[0].node;
      searchTerm = firstActivity.event_scope || firstActivity.event_type || undefined;
      if (!searchTerm) {
        return false;
      }

      const queryResult = await queryAsAdminWithSuccess({
        query: AUDIT_QUERY,
        variables: {
          search: searchTerm,
          types: ['Activity'],
          first: 25,
        },
      });
      foundEdges = queryResult.data.audits.edges;
      return foundEdges.length > 0;
    }, 3000, { message: 'No searchable startup Activity events found' });

    expect(searchTerm).toBeDefined();
    expect(foundEdges.length).toBeGreaterThan(0);
    expect(foundEdges.every((edge) => edge.node.entity_type === 'Activity')).toBe(true);
  });

  it('should search History logs on generated history events', async () => {
    const searchToken = `history-search-${Date.now()}`;
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'AuditHistorySearchReport',
      published: utcDate(),
    });

    try {
      await stixDomainObjectEditField(testContext, ADMIN_USER, report.id, [
        { key: 'description', value: [searchToken] },
      ]);

      let foundEdges: Array<{ node: { entity_type: string } }> = [];
      await awaitUntilCondition(async () => {
        const queryResult = await queryAsAdminWithSuccess({
          query: AUDIT_QUERY,
          variables: {
            search: searchToken,
            types: ['History'],
            first: 25,
          },
        });
        foundEdges = queryResult.data.audits.edges;
        return foundEdges.some((edge) => edge.node.entity_type === 'History');
      }, 3000, { message: 'No searchable generated History event found' });

      expect(foundEdges.some((edge) => edge.node.entity_type === 'History')).toBe(true);
    } finally {
      await stixDomainObjectDelete(testContext, ADMIN_USER, report.id, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });
});

describe('audits distribution query', () => {
  it('should resolve representative.main for stix objects in auditsDistribution', async () => {
    const reportName = `audit-distribution-report-${Date.now()}`;
    const report = await addReport(testContext, ADMIN_USER, {
      name: reportName,
      published: utcDate(),
    });

    try {
      let distribution: Array<any> = [];
      await awaitUntilCondition(async () => {
        const queryResult = await queryAsAdminWithSuccess({
          query: AUDITS_DISTRIBUTION_QUERY,
          variables: {
            field: 'context_data.id',
            operation: 'count',
            types: ['History'],
            limit: 25,
            filters: {
              mode: 'and',
              filters: [{ key: 'contextEntityId', values: [report.id] }],
              filterGroups: [],
            },
          },
        });
        distribution = queryResult.data.auditsDistribution ?? [];
        return distribution.some((item) => item?.entity?.id === report.id && item?.entity?.representative?.main === reportName);
      }, 10000, { message: 'No auditsDistribution result found for created report' });

      const reportDistribution = distribution.find((item) => item?.entity?.id === report.id);
      expect(reportDistribution).toBeDefined();
      expect(reportDistribution.entity.entity_type).toEqual(ENTITY_TYPE_CONTAINER_REPORT);
      expect(reportDistribution.entity.representative.main).toEqual(reportName);
    } finally {
      await stixDomainObjectDelete(testContext, ADMIN_USER, report.id, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });
});

const AUDITS_TIME_SERIES_BREAKDOWN_QUERY = gql`
    query AuditsTimeSeriesBreakdownQuery(
        $field: String!
        $startDate: DateTime!
        $endDate: DateTime
        $interval: String!
        $limit: Int
        $order: OrderingMode
        $includeOther: Boolean
        $types: [String]
        $filters: FilterGroup
    ) {
        auditsTimeSeriesBreakdown(
            field: $field
            startDate: $startDate
            endDate: $endDate
            interval: $interval
            limit: $limit
            order: $order
            includeOther: $includeOther
            types: $types
            filters: $filters
        ) {
            truncated
            dates
            series {
                label
                value
                isOther
                values
                entity {
                    ... on BasicObject {
                        id
                        entity_type
                    }
                    ... on Creator {
                        id
                        entity_type
                        name
                    }
                }
            }
        }
    }
`;

describe('audits time series breakdown query', () => {
  const lastHour = () => new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const breakdownVariables = (variables: Record<string, unknown>) => ({
    startDate: lastHour(),
    interval: 'day',
    types: ['History', 'Activity'],
    ...variables,
  });

  it('should Participant user not be allowed to request an audits breakdown', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY,
      variables: breakdownVariables({ field: 'event_scope' }),
    });
  });

  it('should an unauthenticated user not be allowed to request an audits breakdown', async () => {
    await queryUnauthenticatedIsExpectedForbidden({
      query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY,
      variables: breakdownVariables({ field: 'event_scope' }),
    });
  });

  it('should a user without knowledge access not break down the history', async () => {
    // The platform administrator can see the activity, not the history of the knowledge
    await queryAsUserIsExpectedForbidden(USER_PLATFORM_ADMIN, {
      query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY,
      variables: breakdownVariables({ field: 'event_scope', types: ['History'] }),
    });
  });

  it('should Security user be allowed to request an audits breakdown', async () => {
    const { data } = await queryAsUserWithSuccess(USER_SECURITY, {
      query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY,
      variables: breakdownVariables({ field: 'event_type', types: ['Activity'] }),
    });
    const breakdown = data?.auditsTimeSeriesBreakdown;
    expect(breakdown.series.every((serie: { values: number[] }) => serie.values.length === breakdown.dates.length)).toBe(true);
  });

  it('should refuse a field the logs cannot be broken down by', async () => {
    for (const field of ['context_data.id', 'context_data.message', 'applicant_id']) {
      await queryAsAdminWithError(
        { query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY, variables: breakdownVariables({ field }) },
        'Time series breakdown does not support this field for the history and activity logs',
      );
    }
  });

  it('should break down the history of an entity by scope, user and types', async () => {
    const report = await addReport(testContext, ADMIN_USER, {
      name: `audit-breakdown-report-${Date.now()}`,
      published: utcDate(),
    });
    const reportFilters = {
      mode: 'and',
      filters: [{ key: 'contextEntityId', values: [report.id] }],
      filterGroups: [],
    };
    const queryBreakdown = async (variables: Record<string, unknown>) => {
      const { data } = await queryAsAdminWithSuccess({
        query: AUDITS_TIME_SERIES_BREAKDOWN_QUERY,
        variables: breakdownVariables({ types: ['History'], filters: reportFilters, ...variables }),
      });
      return data.auditsTimeSeriesBreakdown;
    };
    const total = (serie: { values: number[] }) => serie.values.reduce((sum, value) => sum + value, 0);

    try {
      await stixDomainObjectEditField(testContext, ADMIN_USER, report.id, [
        { key: 'description', value: [`audit breakdown ${Date.now()}`] },
      ]);

      let byScope: any;
      await awaitUntilCondition(async () => {
        byScope = await queryBreakdown({ field: 'event_scope' });
        const labels = byScope.series.map((serie: { label: string }) => serie.label);
        return labels.includes('create') && labels.includes('update');
      }, 10000, { message: 'No creation and update found in the history of the report' });

      expect(byScope.truncated).toBe(false);
      const create = byScope.series.find((serie: { label: string }) => serie.label === 'create');
      expect(create.entity).toBeNull();
      expect(total(create)).toEqual(create.value);
      expect(byScope.series.every((serie: { values: number[] }) => serie.values.length === byScope.dates.length)).toBe(true);

      // The user is resolved, the SYSTEM user is never a series
      const byUser = await queryBreakdown({ field: 'user_id' });
      expect(byUser.series.map((serie: { label: string }) => serie.label)).toEqual([ADMIN_USER.id]);
      expect(byUser.series[0].entity).toEqual({ id: ADMIN_USER.id, entity_type: 'User', name: ADMIN_USER.name });

      const byContextType = await queryBreakdown({ field: 'context_data.entity_type' });
      expect(byContextType.series.map((serie: { label: string }) => serie.label)).toEqual([ENTITY_TYPE_CONTAINER_REPORT]);

      const byLogType = await queryBreakdown({ field: 'entity_type' });
      expect(byLogType.series.map((serie: { label: string }) => serie.label)).toEqual(['History']);

      // The top value and the Other series share every event of the report
      const topScope = await queryBreakdown({ field: 'event_scope', limit: 1, includeOther: true });
      expect(topScope.series).toHaveLength(2);
      expect(topScope.truncated).toBe(true);
      const [top, other] = topScope.series;
      expect(other.isOther).toBe(true);
      const allEvents = byScope.series.reduce((sum: number, serie: { values: number[] }) => sum + total(serie), 0);
      expect(total(top) + total(other)).toEqual(allEvents);
    } finally {
      await stixDomainObjectDelete(testContext, ADMIN_USER, report.id, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });
});
