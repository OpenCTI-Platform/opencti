import { logMigration } from '../config/conf';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { FilterMode, VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../modules/vocabulary/vocabulary-types';
import { openVocabularies, seedVocabularyInput } from '../modules/vocabulary/vocabulary-utils';
import { normalizeName } from '../schema/identifier';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Vocabulary add logging to coverage open vocabulary';

// OpenAEV now sends a LOGGING security coverage score: a platform created before seeds the entry here.
// Additive only: an entry an administrator already created under the same name, or carrying it as an alias, is kept as it is
// (the creation resolves an existing entry through its aliases too, and would upsert it).
const LOGGING_KEY = 'logging';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const category = VocabularyCategory.CoverageOv;
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
  const existingNames = new Set(existing.flatMap(({ name, aliases }) => [name, ...(aliases ?? [])]).map(normalizeName));
  const entries = (openVocabularies[category] ?? []).filter(({ key }) => key === LOGGING_KEY && !existingNames.has(normalizeName(key)));
  for (let i = 0; i < entries.length; i += 1) {
    await addVocabulary(context, SYSTEM_USER, seedVocabularyInput(category, entries[i]));
    logMigration.info(`${message} > ${i + 1}/${entries.length} vocabularies added`);
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms. ${entries.length} vocabularies added.`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
