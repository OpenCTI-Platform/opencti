import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

const message = '[MIGRATION] migrate authorized_members to restricted_members';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: 'ctx._source.restricted_members = ctx._source.authorized_members;'
    },
    query: {
      bool: {
        must: [
          {
            exists: {
              field: 'authorized_members'
            }
          }
        ]
      }
    }
  };
  await elUpdateByQueryForMigration(message, READ_DATA_INDICES, updateQuery);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
