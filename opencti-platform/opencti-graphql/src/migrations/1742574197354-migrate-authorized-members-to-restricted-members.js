import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';

const message = '[MIGRATION] migrate authorized_members to restricted_members';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
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
  await elUpdateByQueryForMigration(message, READ_PLATFORM_INDICES, updateQuery);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
