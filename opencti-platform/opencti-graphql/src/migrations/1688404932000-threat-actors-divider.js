import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

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

export const up = async (next) => {
  await splitThreatActorsByCategory('Threat-Actor-Individual', 'Threat-Actor-Group', READ_INDEX_STIX_DOMAIN_OBJECTS);
  next();
};

export const down = async (next) => {
  next();
};
