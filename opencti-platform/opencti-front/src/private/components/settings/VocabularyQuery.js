import { graphql } from 'react-relay';

export const vocabularySearchQuery = graphql`
  query VocabularyQuery($category: VocabularyCategory, $filters: FilterGroup, $search: String) {
    vocabularies(category: $category, filters: $filters, search: $search) {
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
