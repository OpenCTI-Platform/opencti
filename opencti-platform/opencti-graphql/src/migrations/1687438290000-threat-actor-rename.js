import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

const entityTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'ctx._source.entity_type = params.toType;',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: fromType } } },
        ],
      },
    },
  };
  const message = `[MIGRATION] Rewriting entity type from ${fromType} to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

export const up = async (next) => {
  // Change Threat Actor type to Threat Actor Group
  await entityTypeChange('Threat-Actor', 'Threat-Actor-Group', READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS);
  next();
};

export const down = async (next) => {
  next();
};
