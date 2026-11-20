import { Promise } from 'bluebird';
import { logMigration } from '../config/conf';
import { elReplace, ES_MAX_CONCURRENCY } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { FilterMode, VocabularyCategory } from '../generated/graphql';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../modules/vocabulary/vocabulary-types';
import { openVocabularies, systemSubcategoryParentFromDescription } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Moving the category of the System subcategories from their description to parent_name';

// A subcategory created before this migration names its category at the end of its description, "(category: HOST)".
// The link moves to parent_name, the field a rename of the category keeps up to date, and the suffix leaves the description.
// A seeded subcategory whose description an administrator already rewrote without the suffix gets its seeded category back;
// a custom subcategory that names no category keeps none, so the form offers it under every category, as before.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['category'], values: [VocabularyCategory.SystemSubcategoryOv] }],
    filterGroups: [],
  };
  const vocabularies = await fullEntitiesList<BasicStoreEntityVocabulary>(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], {
    indices: [READ_INDEX_STIX_META_OBJECTS],
    filters,
    noFiltersChecking: true,
  });

  const updateVocabulary = async (vocabulary: BasicStoreEntityVocabulary) => {
    // An entry that already names its parent is kept as it is
    if (vocabulary.parent_name) return;
    const parsed = systemSubcategoryParentFromDescription(vocabulary.description);
    if (parsed) {
      await elReplace(context, vocabulary._index, vocabulary.id, { doc: { parent_name: parsed.parentName, description: parsed.description } });
      return;
    }
    const seeded = openVocabularies.system_subcategory_ov.find(({ key }) => key === vocabulary.name);
    if (seeded?.parent_name) {
      await elReplace(context, vocabulary._index, vocabulary.id, { doc: { parent_name: seeded.parent_name } });
    }
  };

  await Promise.map(vocabularies, updateVocabulary, { concurrency: ES_MAX_CONCURRENCY });

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
