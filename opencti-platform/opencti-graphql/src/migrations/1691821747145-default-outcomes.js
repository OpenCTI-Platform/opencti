import { logApp } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { addNotifier } from '../modules/notifier/notifier-domain';
import { DEFAULT_TEAM_DIGEST_MESSAGE, DEFAULT_TEAM_MESSAGE } from '../modules/notifier/notifier-statics';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Renaming outcomes to notifiers and create defaults';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const updateQuery = {
    script: {
      params: { outcomes: 'outcomes' },
      source: 'ctx._source.notifiers = ctx._source.outcomes; ctx._source.remove(params.outcomes) ',
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
  await Promise.all([DEFAULT_TEAM_MESSAGE, DEFAULT_TEAM_DIGEST_MESSAGE]
    .map((notifier) => addNotifier(context, SYSTEM_USER, notifier)));
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
