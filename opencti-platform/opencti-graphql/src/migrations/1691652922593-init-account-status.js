import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { DEFAULT_ACCOUNT_STATUS } from '../config/conf';

export const up = async (next) => {
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
    index: [READ_INDEX_STIX_META_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateUserQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
  next();
};

export const down = async (next) => {
  next();
};
