import { graphql } from 'react-relay';

const usersLinesSearchQuery = graphql`
  query UsersLinesSearchQuery(
      $first: Int, $search: String,
      $orderBy: UsersOrdering
      $orderMode: OrderingMode
  ) {
    users(first: $first, search: $search, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          entity_type
          name
          user_email
        }
      }
    }
  }
`;

export default usersLinesSearchQuery;
