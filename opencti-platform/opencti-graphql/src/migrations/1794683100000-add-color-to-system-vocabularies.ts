import { Promise } from 'bluebird';
import { logMigration } from '../config/conf';
import { elReplace, ES_MAX_CONCURRENCY } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { FilterMode, VocabularyCategory } from '../generated/graphql';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../modules/vocabulary/vocabulary-types';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Adding the seeded colour to the System asset vocabularies';

// The categories whose built-in entries carry a seeded colour
const COLORED_CATEGORIES = [
  VocabularyCategory.SystemCategoryOv,
  VocabularyCategory.SystemCriticalityOv,
  VocabularyCategory.SystemEnvironmentOv,
  VocabularyCategory.SystemInternetFacingOv,
];

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['category'], values: COLORED_CATEGORIES }],
    filterGroups: [],
  };
  const vocabularies = await fullEntitiesList<BasicStoreEntityVocabulary>(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], {
    indices: [READ_INDEX_STIX_META_OBJECTS],
    filters,
    noFiltersChecking: true,
  });

  const updateVocabulary = async (vocabulary: BasicStoreEntityVocabulary) => {
    // A colour an administrator already set is kept
    if (vocabulary.color) return;
    const seeded = (openVocabularies[vocabulary.category] ?? []).find(({ key }) => key === vocabulary.name);
    if (seeded?.color) {
      await elReplace(context, vocabulary._index, vocabulary.id, { doc: { color: seeded.color } });
    }
  };

  await Promise.map(vocabularies, updateVocabulary, { concurrency: ES_MAX_CONCURRENCY });

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
