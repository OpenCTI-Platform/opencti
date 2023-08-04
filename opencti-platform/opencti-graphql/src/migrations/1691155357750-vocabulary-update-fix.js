import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

export const up = async (next) => {
  const query = {
    script: {
      source: "if(!(ctx._source['secondary_motivations'] instanceof List)) ctx._source['secondary_motivations'] = [ctx._source['secondary_motivations']]"
    },
    query: {
      bool: {
        must: [
          {
            exists: { field: 'secondary_motivations' }
          }
        ]
      }
    }
  };
  elUpdateByQueryForMigration('[MIGRATION] Fix broken secondary_motivations', READ_DATA_INDICES, query);
  next();
};

export const down = async (next) => {
  next();
};
