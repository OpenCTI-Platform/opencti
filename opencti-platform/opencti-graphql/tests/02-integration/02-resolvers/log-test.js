import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { elLoadByStixId } from '../../../src/database/elasticSearch';

const LIST_QUERY = gql`
  query logs(
    $first: Int
    $after: ID
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: [LogsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    logs(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
      search: $search
    ) {
      edges {
        node {
          id
          event_type
          event_date
          event_message
          event_data
        }
      }
    }
  }
`;

describe('Note resolver standard behavior', () => {
  it('should list logs', async () => {
    const identity = await elLoadByStixId('identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132');
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 100,
        filters: [{ key: 'entity_id', values: [identity.internal_id] }],
      },
    });
    expect(queryResult.data.logs.edges.length).toBeGreaterThanOrEqual(1);
  });
  it('should list logs relations', async () => {
    const identity = await elLoadByStixId('identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f');
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 100,
        filters: [{ key: 'connection_id', values: [identity.internal_id], operator: 'wildcard' }],
      },
    });
    expect(queryResult.data.logs.edges.length).toBeGreaterThanOrEqual(1);
  });
});
