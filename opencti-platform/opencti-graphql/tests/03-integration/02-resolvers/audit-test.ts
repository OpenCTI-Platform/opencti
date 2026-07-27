import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  awaitUntilCondition,
  queryAsAdminWithSuccess,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
  queryUnauthenticatedIsExpectedForbidden,
} from '../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_PARTICIPATE, USER_SECURITY } from '../../utils/testQuery';
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
    }, 1000, 20, true, 'No searchable startup Activity events found');

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
      }, 1000, 20, true, 'No searchable generated History event found');

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
      }, 1000, 20, true, 'No auditsDistribution result found for created report');

      const reportDistribution = distribution.find((item) => item?.entity?.id === report.id);
      expect(reportDistribution).toBeDefined();
      expect(reportDistribution.entity.entity_type).toEqual(ENTITY_TYPE_CONTAINER_REPORT);
      expect(reportDistribution.entity.representative.main).toEqual(reportName);
    } finally {
      await stixDomainObjectDelete(testContext, ADMIN_USER, report.id, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });
});
