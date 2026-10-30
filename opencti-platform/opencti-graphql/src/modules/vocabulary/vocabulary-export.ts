import { normalizeName } from '../../schema/identifier';
import type { VocabularyCategory } from '../../generated/graphql';
import { cleanVocabularyAliases, isSameAliasSet, openVocabularies } from './vocabulary-utils';
import type { BasicStoreEntityVocabulary } from './vocabulary-types';
import { vocabularyEntryImportSchema } from './vocabulary-import-schema';

// The fields of an entry in the configuration: the ones the import accepts, so the import takes the export back as is
const VOCABULARY_EXPORT_FIELDS = Object.keys(vocabularyEntryImportSchema.shape) as (keyof BasicStoreEntityVocabulary)[];

// The entry the platform creates itself (see openVocabularies), by its name whatever its case
const findDefaultEntry = ({ category, name }: Pick<BasicStoreEntityVocabulary, 'category' | 'name'>) => {
  return (openVocabularies[category] ?? []).find(({ key }) => normalizeName(key) === normalizeName(name));
};

// An entry the platform creates is exported only when it was modified; any other entry is custom. The platform creates every entry
// without description as '', without aliases as [], without order as 0, and does not keep as an alias the name of the entry
// (the default 'low' with the alias 'low' is stored without alias): the defaults are compared as the platform stores them.
export const isVocabularyExportable = (vocabulary: BasicStoreEntityVocabulary) => {
  const defaultEntry = findDefaultEntry(vocabulary);
  if (!defaultEntry) {
    return true;
  }
  return (vocabulary.description ?? '') !== (defaultEntry.description ?? '')
    || !isSameAliasSet(cleanVocabularyAliases(vocabulary.name, vocabulary.aliases), cleanVocabularyAliases(defaultEntry.key, defaultEntry.aliases))
    || (vocabulary.order ?? 0) !== (defaultEntry.order ?? 0);
};

// An entry in the import format of its category. A missing value is left out: the import gives it its default
const getVocabularyEntryConfiguration = (vocabulary: BasicStoreEntityVocabulary) => {
  const presentFields = VOCABULARY_EXPORT_FIELDS.filter((field) => (vocabulary[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, vocabulary[field]]));
};

// The categories that have something to export: at least one custom or modified entry
export const getExportableVocabularyCategories = (vocabularies: BasicStoreEntityVocabulary[]) => {
  return [...new Set(vocabularies.filter(isVocabularyExportable).map(({ category }) => category))];
};

// A category in the import format: the custom entries and the modified ones of the category, in the order of the given list
export const getVocabularyCategoryConfigPresetConfiguration = (category: VocabularyCategory, vocabularies: BasicStoreEntityVocabulary[]) => {
  const entries = vocabularies.filter((vocabulary) => vocabulary.category === category && isVocabularyExportable(vocabulary));
  return { category, entries: entries.map(getVocabularyEntryConfiguration) };
};
