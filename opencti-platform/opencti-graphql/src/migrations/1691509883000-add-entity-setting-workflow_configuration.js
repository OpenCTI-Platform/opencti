import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  // TODO Q? Apply only on Internal Objects?
  const query = {
    script: {
      source: `
        if (ctx._source.target_type == 'Stix-Cyber-Observable' || ctx._source.target_type == 'Artifact') {
          ctx._source.workflow_configuration = false;
        } else {
          ctx._source.workflow_configuration = true;
        }`
    },
    query: {
      match: {
        entity_type: 'EntitySetting'
      }
    }
  };
  await elUpdateByQueryForMigration('[MIGRATION] Add entity setting workflow_configuration', READ_INDEX_INTERNAL_OBJECTS, query);
  next();
};

export const down = async (next) => {
  next();
};
