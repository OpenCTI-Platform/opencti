import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { useVocabularyCategoryQuery, VocabularyCategory } from './__generated__/useVocabularyCategoryQuery.graphql';
import { ApplicationError, environment } from '../../relay/environment';

export const vocabCategoriesQuery = graphql`
  query useVocabularyCategoryQuery {
    vocabularyCategories {
      key
      entity_types
      fields {
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
      fields {
        key
        required
        multiple
      }
    }
  }
`;

const queryRef = loadQuery<useVocabularyCategoryQuery>(environment, vocabCategoriesQuery, {});

const useVocabularyCategory = () => {
  const data = usePreloadedQuery<useVocabularyCategoryQuery>(vocabCategoriesQuery, queryRef);
  const vocabularyCategories = () => (data.vocabularyCategories.map(({ key }) => key)) as VocabularyCategory[];
  const categories = vocabularyCategories();

  const typeToCategory = (type: string): VocabularyCategory => {
    const formattedType = type.toLowerCase().replaceAll('-', '_');
    const value = categories.find((v) => v === formattedType);
    if (!value) {
      throw new ApplicationError(`Invalid vocabulary category ${type}`);
    }
    return value;
  };

  const fieldToCategory = (entityType: string, field: string): VocabularyCategory | undefined => {
    const entityCategories = data.vocabularyCategories.filter((v) => v.entity_types.includes(entityType));
    const findCategory = entityCategories.find((e) => e.fields.map((f) => f.key).includes(field));
    return findCategory?.key;
  };

  const isVocabularyField = (entityType: string, field: string): boolean => {
    return fieldToCategory(entityType, field) !== undefined;
  };

  return {
    categories,
    isVocabularyField,
    fieldToCategory,
    typeToCategory,
    categoriesOptions: categories.map((cat) => ({ value: cat, label: cat })),
  };
};

export default useVocabularyCategory;
