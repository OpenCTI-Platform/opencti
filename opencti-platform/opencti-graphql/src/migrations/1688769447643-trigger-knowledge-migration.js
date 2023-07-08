import { logApp } from '../config/conf';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] Adding trigger scope and authorized_capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { trigger_scope: 'knowledge', capabilities: ['SETTINGS_SETACCESSES'] },
      source: 'ctx._source.trigger_scope = params.trigger_scope; ctx._source.authorized_authorities = params.capabilities',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Trigger' } } },
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
