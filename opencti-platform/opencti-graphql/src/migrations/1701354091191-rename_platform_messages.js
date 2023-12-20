import { logApp } from '../config/conf';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] Renaming platform messages attribute';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { messages: 'messages' },
      source: 'ctx._source.platform_messages = ctx._source.messages; ctx._source.remove(params.messages) ',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Settings' } } },
        ],
      },
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
