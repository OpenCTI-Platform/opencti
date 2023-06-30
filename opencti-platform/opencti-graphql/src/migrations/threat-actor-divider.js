import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

const splitThreatActorsByCategory = async (indices) => {
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
      term: { 'entity_type.keyword': { value: 'Threat-Actor-Group' } },
    },
  };

  const message = '[MIGRATION] Splitting Threat-Actor into Threat-Actor-Group and Threat-Actor-Individual';
  try {
    await elUpdateByQueryForMigration(message, indices, updateIndividualQuery);
  } catch (err) {
    throw new DatabaseError('Error updating elastic', { error: err });
  }
};

export const up = async (next) => {
  await splitThreatActorsByCategory(READ_INDEX_INTERNAL_OBJECTS);
  next();
};

export const down = async (next) => {
  next();
};
