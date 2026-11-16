import { graphql, useLazyLoadQuery } from 'react-relay';
import { useVocabularyEntriesQuery, VocabularyCategory } from './__generated__/useVocabularyEntriesQuery.graphql';
import { vocabularyColor, vocabularyDescriptionForDisplay } from '../vocabulary/vocabularyDisplay';

export const vocabularyEntriesQuery = graphql`
  query useVocabularyEntriesQuery($category: VocabularyCategory!) {
    vocabularies(category: $category, first: 500, orderBy: order, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          color
          order
        }
      }
    }
  }
`;

export interface VocabularyEntry {
  name: string;
  description?: string;
  color?: string;
  order?: number | null;
}

/**
 * The entries of one vocabulary, keyed by value, with the colour and the display description of each.
 * Read once per category from the store (store-or-network): every tag of the same category shares one request.
 * Suspends: render it under a Suspense boundary whose fallback is the neutral tag.
 */
const useVocabularyEntries = (category: string): Map<string, VocabularyEntry> => {
  const data = useLazyLoadQuery<useVocabularyEntriesQuery>(
    vocabularyEntriesQuery,
    { category: category as VocabularyCategory },
    { fetchPolicy: 'store-or-network' },
  );
  const entries = new Map<string, VocabularyEntry>();
  (data.vocabularies?.edges ?? []).forEach(({ node }) => {
    entries.set(node.name, {
      name: node.name,
      description: vocabularyDescriptionForDisplay(node.description),
      color: vocabularyColor(node.color),
      order: node.order,
    });
  });
  return entries;
};

export default useVocabularyEntries;
