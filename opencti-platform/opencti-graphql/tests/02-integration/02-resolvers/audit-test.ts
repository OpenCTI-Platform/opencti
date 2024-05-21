import { describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
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

  it('should Participant/Editor user not be allowed to request audit data.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: AUDIT_QUERY,
      variables: {
        types: ['Activity'],
        first: 10
      },
    });
  });

  it('should Security user not be allowed to request knowledge data.', async () => {
    await queryAsUserIsExpectedForbidden(USER_SECURITY.client, {
      query: AUDIT_QUERY,
      variables: {
        types: ['History'],
        first: 10
      },
    });
  });
});
