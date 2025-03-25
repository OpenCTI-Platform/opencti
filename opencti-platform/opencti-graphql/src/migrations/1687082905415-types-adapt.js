import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { convertTypeToStixType } from '../database/stix-2-1-converter';
import { logApp } from '../config/conf';

const entityTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType, prefix: convertTypeToStixType(toType) },
      source: "ctx._source.entity_type = params.toType; ctx._source.standard_id = (params.prefix + '--' + ctx._source.standard_id.splitOnToken('--')[1]);",
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
  return elUpdateByQueryForMigration(message, indices, updateQuery);
};

export const up = async (next) => {
  logApp.info('[MIGRATION] Types adapt');
  await entityTypeChange('Task', 'BackgroundTask', READ_INDEX_INTERNAL_OBJECTS);
  next();
};

export const down = async (next) => {
  next();
};
