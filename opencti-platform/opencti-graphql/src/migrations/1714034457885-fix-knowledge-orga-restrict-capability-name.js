import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';

export const up = async (next) => {
  const capabilityName = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
  const standardId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capabilityName });
  const updateQuery = {
    script: {
      params: { name: capabilityName, standardId },
      source: 'ctx._source.name = params.name; ctx._source.standard_id = params.standardId',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Capability' } } },
          { term: { 'name.keyword': { value: 'KNOWLEDGE_KNUPDATE_KNOWLEDGE_KNUPDATE_KNORGARESTRICT' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Fix Restrict organization access capability name',
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
