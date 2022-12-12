import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const vocabularySearchQuery = graphql`
  query VocabularyQuery($category: VocabularyCategory) {
    vocabularies(category: $category) {
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
