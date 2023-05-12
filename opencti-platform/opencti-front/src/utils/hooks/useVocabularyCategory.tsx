import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { useState } from 'react';
import {
  useVocabularyCategoryQuery,
  VocabularyCategory,
} from './__generated__/useVocabularyCategoryQuery.graphql';
import { ApplicationError, environment } from '../../relay/environment';

export interface VocabularyDefinition {
  key: string;
  description: string;
  entity_types: string[];
  fields: {
    key: string;
    required: boolean;
    multiple: boolean;
  }[];
}

export const vocabCategoriesQuery = graphql`
  query useVocabularyCategoryQuery {
    vocabularyCategories {
      key
      description
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
    entity_type
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

const queryRef = loadQuery<useVocabularyCategoryQuery>(
  environment,
  vocabCategoriesQuery,
  {},
);

const useVocabularyCategory = () => {
  const data = usePreloadedQuery<useVocabularyCategoryQuery>(
    vocabCategoriesQuery,
    queryRef,
  );
  const vocabularyCategories = () => data.vocabularyCategories.map(({ key }) => key) as VocabularyCategory[];
  const categories = vocabularyCategories();
  const typeToCategory = (type: string): VocabularyCategory => {
    const formattedType = type.toLowerCase().replaceAll('-', '_');
    const value = categories.find((v) => v === formattedType);
    if (!value) {
      throw new ApplicationError(`Invalid vocabulary category ${type}`);
    }
    return value;
  };
  const fieldToCategory = (
    entityType: string,
    field: string,
  ): VocabularyCategory | undefined => {
    const entityCategories = data.vocabularyCategories.filter((v) => v.entity_types.includes(entityType));
    const findCategory = entityCategories.find((e) => e.fields.map((f) => f.key).includes(field));
    return findCategory?.key;
  };
  const isVocabularyField = (entityType: string, field: string): boolean => {
    return fieldToCategory(entityType, field) !== undefined;
  };

  const allFields = data.vocabularyCategories.flatMap((vc) => vc.fields);

  return {
    categories,
    fields: allFields.map(({ key }) => key),
    getFieldDefinition: (f: string) => allFields.find(({ key }) => f === key),
    isVocabularyField,
    fieldToCategory,
    typeToCategory,
    categoriesOptions: categories.map((cat) => ({ value: cat, label: cat })),
  };
};

export const useVocabularyCategoryAsQuery = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('name');
  const [orderAsc, setOrderAsc] = useState(true);
  const data = usePreloadedQuery<useVocabularyCategoryQuery>(
    vocabCategoriesQuery,
    queryRef,
  );
  const definitions = data.vocabularyCategories;
  const categories = definitions
    .filter(({ key }) => key.includes(searchTerm))
    .sort((a, b) => {
      let value;
      switch (sortBy) {
        case 'description':
          value = (a.description ?? '').localeCompare(b.description ?? '');
          break;
        default:
          value = (a.key ?? '').localeCompare(b.key ?? '');
          break;
      }
      return orderAsc ? value : -value;
    });
  return {
    handleSort: (field: string, order: boolean) => {
      if (field) {
        setSortBy(field);
      }
      if (order !== orderAsc) {
        setOrderAsc(order);
      }
    },
    handleSearch: (value: string) => setSearchTerm(value),
    searchTerm,
    orderAsc,
    sortBy,
    categories: categories.map((cat) => ({ node: cat })),
  };
};

export default useVocabularyCategory;
