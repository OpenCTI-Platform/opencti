import { Promise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { elRawUpdateByQuery, elReplace, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { VocabularyCategory } from '../generated/graphql';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Adding default order value to opinion open vocabulary');

  const updateEntityQuery = {
    script: {
      params: { order: 0 },
      source: 'ctx._source.order = params.order;',
    },
    query: {
      term: { 'entity_type.keyword': { value: ENTITY_TYPE_VOCABULARY } }
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_STIX_META_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateEntityQuery
  })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });

  const defaultVocabularies = new Map((openVocabularies.opinion_ov ?? []).map((v) => [v.key, v]));
  const VocabularyFilters = [
    'name',
    'category',
    'description',
    'entity_types',
    'aliases',
  ];
  const filters = {
    mode: 'and',
    filters: [{
      key: VocabularyFilters,
      values: [VocabularyCategory.OpinionOv]
    }],
    filterGroups: [],
  };
  const vocabularies = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], {
    indices: [READ_INDEX_STIX_META_OBJECTS],
    connectionFormat: false,
    filters,
    noFiltersChecking: true,
  });

  const updateVocabulary = async (vocabulary) => {
    const defaultVocabulary = defaultVocabularies.get(vocabulary.name);
    if (defaultVocabulary) {
      const update = { order: defaultVocabulary.order };
      await elReplace(vocabulary._index, vocabulary, update);
    }
  };

  await Promise.map(vocabularies, updateVocabulary, { concurrency: ES_MAX_CONCURRENCY });

  logApp.info(`[MIGRATION] Adding default order value to opinion open vocabulary done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
