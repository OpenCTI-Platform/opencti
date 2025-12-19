import { graphql } from 'react-relay';

export const labelsSearchQuery = graphql`
  query LabelsQuerySearchQuery($search: String, $orderBy: LabelsOrdering, $orderMode: OrderingMode) {
    labels(search: $search, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;
