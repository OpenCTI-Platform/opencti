import { logMigration } from '../config/conf';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { FilterMode, VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../modules/vocabulary/vocabulary-types';
import { openVocabularies, seedVocabularyInput } from '../modules/vocabulary/vocabulary-utils';
import { normalizeName } from '../schema/identifier';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Vocabulary add the Source code asset category and its subcategories to System';

// The OpenAEV asset taxonomy gained the SOURCE_CODE category: a platform created before seeds it here.
// Additive only: an entry an administrator already created under the same name is kept as it is.
const SOURCE_CODE_ENTRIES: Array<{ category: VocabularyCategory; keys: string[] }> = [
  { category: VocabularyCategory.SystemCategoryOv, keys: ['SOURCE_CODE'] },
  {
    category: VocabularyCategory.SystemSubcategoryOv,
    keys: ['CODE_REPOSITORY', 'CI_CD_PIPELINE', 'PACKAGE_REGISTRY', 'SOFTWARE_PACKAGE', 'CODE_OTHER'],
  },
];

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  let count = 0;
  for (let c = 0; c < SOURCE_CODE_ENTRIES.length; c += 1) {
    const { category, keys } = SOURCE_CODE_ENTRIES[c];
    const filters = {
      mode: FilterMode.And,
      filters: [{ key: ['category'], values: [category] }],
      filterGroups: [],
    };
    const existing = await fullEntitiesList<BasicStoreEntityVocabulary>(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], {
      indices: [READ_INDEX_STIX_META_OBJECTS],
      filters,
      noFiltersChecking: true,
    });
    const existingNames = new Set(existing.map(({ name }) => normalizeName(name)));
    const entries = (openVocabularies[category] ?? []).filter(({ key }) => keys.includes(key) && !existingNames.has(normalizeName(key)));
    for (let i = 0; i < entries.length; i += 1) {
      await addVocabulary(context, SYSTEM_USER, seedVocabularyInput(category, entries[i]));
      count += 1;
    }
  }
  logMigration.info(`${message} > done. ${count} vocabularies added.`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
