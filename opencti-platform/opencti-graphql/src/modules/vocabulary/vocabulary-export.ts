import type { VocabularyCategory } from '../../generated/graphql';
import type { BasicStoreEntityVocabulary } from './vocabulary-types';
import { vocabularyEntryImportSchema } from './vocabulary-import-schema';

// The fields of an entry in the configuration: the ones the import accepts, so the import takes the export back as is
const VOCABULARY_EXPORT_FIELDS = Object.keys(vocabularyEntryImportSchema.shape) as (keyof BasicStoreEntityVocabulary)[];

// An entry in the import format of its category. A missing value is left out: the import gives it its default
const getVocabularyEntryConfiguration = (vocabulary: BasicStoreEntityVocabulary) => {
  const presentFields = VOCABULARY_EXPORT_FIELDS.filter((field) => (vocabulary[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, vocabulary[field]]));
};

// The categories that have an entry, the ones of the platform included
export const getVocabularyCategories = (vocabularies: BasicStoreEntityVocabulary[]) => {
  return [...new Set(vocabularies.map(({ category }) => category))];
};

// A category in the import format: all its entries, the ones of the platform included, in the order of the given list
export const exportVocabularyCategory = (category: VocabularyCategory, vocabularies: BasicStoreEntityVocabulary[]) => {
  const entries = vocabularies.filter((vocabulary) => vocabulary.category === category);
  return { category, entries: entries.map(getVocabularyEntryConfiguration) };
};
