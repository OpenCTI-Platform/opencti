import { OrderingMode, type VocabularyCategory, VocabularyOrdering } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import { getVocabularyCategories, exportVocabularyCategory } from '../../vocabulary/vocabulary-export';
import { findAllVocabularies } from '../../vocabulary/vocabulary-domain';
import { importVocabularyCategory } from '../../vocabulary/vocabulary-import';
import type { BasicStoreEntityVocabulary } from '../../vocabulary/vocabulary-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetListItemsArgs } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { matchesListArgs, pageConfigPresetItems, taxonomyGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const VOCABULARIES_FAMILY_ID = 'vocabularies';

// The user sees the categories, not their entries: a category is exported and imported with its entries. Its id is the category itself.
const toCategoryItem = (category: VocabularyCategory, vocabularies: BasicStoreEntityVocabulary[]): ConfigPresetItemDefinition => ({
  id: category,
  label: category,
  translatable: false,
  exporter: async () => exportVocabularyCategory(category, vocabularies),
});

// The categories to export are all the ones that have an entry, the entries of the platform included: they are all read here, not by the engine. By category.
const getExportableItems = async (context: AuthContext, user: AuthUser) => {
  const vocabularies = await findAllVocabularies(context, user, {
    orderBy: [VocabularyOrdering.Category, VocabularyOrdering.Order, VocabularyOrdering.Name],
    orderMode: OrderingMode.Asc,
  });
  return getVocabularyCategories(vocabularies).map((category) => toCategoryItem(category, vocabularies));
};

const matchesSearch = (item: ConfigPresetItemDefinition, search?: string | null) => {
  return !search || item.label.toLowerCase().includes(search.toLowerCase());
};

const vocabulariesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode) => {
    const { category } = item.configuration;
    const hasCategory = typeof category === 'string';
    const label = { label: hasCategory ? category : item.id, translatable: false };
    // The bundle id of a category is the category
    if (hasCategory && category !== item.id) {
      return { ...label, exists: false, conflict: false, status: 'failed', reason: 'The id of the vocabulary category does not match its category' };
    }
    return toComputedItem(label, await importVocabularyCategory(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importVocabularyCategory(context, user, item.configuration, { mode }), computed);
  },
};

const filterItems = (items: ConfigPresetItemDefinition[], args: ConfigPresetListItemsArgs) => {
  return items.filter((item) => matchesListArgs(item, args) && matchesSearch(item, args.search));
};

// Vocabularies: all the categories, listed and paged in memory. A category is exported with all its entries, the ones of the platform included, and
// imported by adding the entries the platform does not have: the ones it has are skipped, never changed or deleted. There is no mode to choose.
export const vocabulariesFamily: ConfigPresetFamilyDefinition = {
  importer: vocabulariesImporter,
  id: VOCABULARIES_FAMILY_ID,
  label: 'Vocabularies',
  description: 'Vocabulary categories and their entries',
  group: taxonomyGroup,
  directory: 'taxonomy/vocabularies',
  listItems: async (context, user, args) => {
    return pageConfigPresetItems(filterItems(await getExportableItems(context, user), args), args);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    return filterItems(await getExportableItems(context, user), { ids, excludedIds });
  },
};
