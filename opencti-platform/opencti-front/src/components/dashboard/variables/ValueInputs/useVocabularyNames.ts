import { useEffect, useState } from 'react';
import { fetchQuery, useRelayEnvironment } from 'react-relay';
import { vocabularySearchQuery } from '@components/settings/VocabularyQuery';
import type { VocabularyCategory, VocabularyQuery } from '@components/settings/__generated__/VocabularyQuery.graphql';

// Names of the vocabularies of a category, the values of a vocabulary variable. None until a category is chosen.
const useVocabularyNames = (category: string | undefined): string[] => {
  const environment = useRelayEnvironment();
  const [names, setNames] = useState<string[]>([]);

  useEffect(() => {
    if (!category) return undefined;
    const subscription = fetchQuery<VocabularyQuery>(
      environment,
      vocabularySearchQuery,
      { category: category as VocabularyCategory },
      { fetchPolicy: 'store-or-network' },
    ).subscribe({
      next: (data) => setNames((data.vocabularies?.edges ?? []).map(({ node }) => node.name)),
    });
    return () => subscription.unsubscribe();
  }, [environment, category]);

  return names;
};

export default useVocabularyNames;
