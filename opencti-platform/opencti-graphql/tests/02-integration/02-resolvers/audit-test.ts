import { describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsUserIsExpectedForbidden, queryAsUserWithSuccess, queryUnauthenticatedIsExpectedForbidden } from '../../utils/testQueryHelper';
import { USER_PARTICIPATE, USER_SECURITY } from '../../utils/testQuery';

describe('Log/Audit resolver rights management checks', () => {
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

  it('should Participant user not be allowed to request audit data.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10
      },
    });
  });

  it('should Security user be allowed to request audit data.', async () => {
    await queryAsUserWithSuccess(USER_SECURITY.client, {
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10
      },
    });
  });

  it('Should user cannot access audit and knowledge data if not authenticated', async () => {
    await queryUnauthenticatedIsExpectedForbidden({
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10
      },
    });
  });
});
