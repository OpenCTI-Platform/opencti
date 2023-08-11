import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

export const up = async (next) => {
  const query = {
    script: {
      source: 'ctx._source.workflow_configuration = true;'
    },
    query: {
      match: {
        entity_type: ENTITY_TYPE_ENTITY_SETTING
      }
    }
  };
  await elUpdateByQueryForMigration('[MIGRATION] Add entity setting workflow_configuration', READ_INDEX_INTERNAL_OBJECTS, query);
  next();
};

export const down = async (next) => {
  next();
};
