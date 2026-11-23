import { graphql } from 'react-relay';

export const vocabularySearchQuery = graphql`
  query VocabularyQuery(
    $category: VocabularyCategory
    $filters: FilterGroup
    $search: String
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
  ) {
    vocabularies(category: $category, filters: $filters, search: $search, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          category {
            key
            fields {
              key
            }
          }
        }
      }
    }
  }
`;
