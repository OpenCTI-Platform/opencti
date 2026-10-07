import { Promise } from 'bluebird';
import { logMigration } from '../config/conf';
import { elReplace, ES_MAX_CONCURRENCY } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { FilterMode, VocabularyCategory } from '../generated/graphql';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../modules/vocabulary/vocabulary-types';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Adding order to coverage open vocabulary';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // get existing vocabulary in coverage_ov category
  const filters = {
    mode: FilterMode.And,
    filters: [{
      key: ['category'],
      values: [VocabularyCategory.CoverageOv],
    }],
    filterGroups: [],
  };
  const coverageVocabularies = await fullEntitiesList<BasicStoreEntityVocabulary>(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], {
    indices: [READ_INDEX_STIX_META_OBJECTS],
    filters,
    noFiltersChecking: true,
  });

  // Add order
  const defaultVocabularies = new Map((openVocabularies.coverage_ov ?? []).map((v) => [v.key, v]));
  const updateCoverageVocabulary = async (vocabulary: BasicStoreEntityVocabulary) => {
    const defaultVocabulary = defaultVocabularies.get(vocabulary.name);
    if (defaultVocabulary?.order !== undefined) {
      const patch = { order: defaultVocabulary.order };
      await elReplace(context, vocabulary._index, vocabulary.id, { doc: patch });
    }
  };

  await Promise.map(coverageVocabularies, updateCoverageVocabulary, { concurrency: ES_MAX_CONCURRENCY });

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
