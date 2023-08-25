import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { logApp, DEFAULT_ACCOUNT_STATUS } from '../config/conf';

const message = '[MIGRATION] Initializing Account Status';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateUserQuery = {
    script: {
      params: { status: DEFAULT_ACCOUNT_STATUS },
      source: 'ctx._source.account_status = params.status;',
    },
    query: {
      term: { 'entity_type.keyword': { value: 'User' } }
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateUserQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
