import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary, deleteVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';

const splitThreatActorsByCategory = async (toType, fromType, indices) => {
  const updateIndividualQuery = {
    script: {
      params: { toType: 'Threat-Actor-Individual' },
      source: `
        if (ctx._source.resource_level === 'individual') {
          ctx._source.entity_type = params.toType;
        }
      `,
    },
    query: {
      bool: {
        should: [
          { term: { 'resource_level.keyword': { value: 'individual' } } },
        ],
        minimum_should_match: 1
      },
    },
  };

  const message = '[MIGRATION] Splitting Threat-Actor into Threat-Actor-Group and Threat-Actor-Individual';
  return elUpdateByQueryForMigration(message, indices, updateIndividualQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const vocabularySplit = async () => {
  const context = executionContext('migration');
  const categories = [VocabularyCategory];
  for (let indexCategory = 0; indexCategory < categories.length; indexCategory += 1) {
    const category = categories[indexCategory];
    const vocabularies = openVocabularies[category] ?? [];
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description, aliases } = vocabularies[i];
      const data = {
        name: key,
        description: description ?? '',
        aliases: aliases ?? [],
        category,
        buildIn: builtInOv.includes(category)
      };
      const duplicateCategory = { ...data };
      await deleteVocabularyCategory(category);
      await addVocabularyCategory(duplicateCategory);
    }
  }
  async function deleteVocabularyCategory(category) {
    await deleteVocabulary(context, SYSTEM_USER, category);
  }
  async function addVocabularyCategory(category) {
    await addVocabulary(context, SYSTEM_USER, category);
  }
};

export const up = async (next) => {
  await vocabularySplit();
  await splitThreatActorsByCategory('Threat-Actor-Individual', 'Threat-Actor-Group', READ_INDEX_STIX_DOMAIN_OBJECTS);
  next();
};

export const down = async (next) => {
  next();
};
