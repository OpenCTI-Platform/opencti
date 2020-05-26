import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query subTypes(
    $first: Int
    $after: ID
    $orderBy: SubTypesOrdering
    $orderMode: OrderingMode
    $type: String!
    $includeParents: Boolean
    $search: String
  ) {
    subTypes(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      type: $type
      includeParents: $includeParents
      search: $search
    ) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

describe('SubType resolver standard behavior', () => {
  it('should list subTypes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 50, type: 'Stix-Observable' } });
    expect(queryResult.data.subTypes.edges.length).toEqual(30);
  });
});
