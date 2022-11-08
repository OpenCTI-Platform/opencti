import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { useVocabularyCategoryQuery, VocabularyCategory } from './__generated__/useVocabularyCategoryQuery.graphql';
import { ApplicationError, environment } from '../../relay/environment';

export const vocabCategoriesQuery = graphql`
  query useVocabularyCategoryQuery {
    vocabularyCategories{
      key
      entity_types
      fields{
        key
        required
        multiple
      }
    }
  }
`;

export const vocabFragment = graphql`
  fragment useVocabularyCategory_Vocabularynode on Vocabulary {
    id
    name
    description
    usages
    aliases
    builtIn
    category {
      key
      entity_types
      fields{
        key
        required
        multiple
      }
    }
  }
`;

let VocabularyCategories: VocabularyCategory[] = [];
const queryRef = loadQuery<useVocabularyCategoryQuery>(environment, vocabCategoriesQuery, {});

const useVocabularyCategory = () => {
  const data = usePreloadedQuery<useVocabularyCategoryQuery>(vocabCategoriesQuery, queryRef);
  if (!VocabularyCategories || data.vocabularyCategories.length > VocabularyCategories.length) {
    VocabularyCategories = (data.vocabularyCategories.map(({ key }) => key)) as VocabularyCategory[];
  }

  const typeToCategory = (type: string): VocabularyCategory => {
    const value = VocabularyCategories.find((v) => v === type.toLowerCase().replaceAll('-', '_'));
    if (!value) {
      throw new ApplicationError(`Invalid vocabulary category ${type}`);
    }
    return value;
  };

  return {
    categories: VocabularyCategories,
    typeToCategory,
    categoriesOptions: VocabularyCategories.map((cat) => ({ value: cat, label: cat })),
  };
};

export default useVocabularyCategory;
