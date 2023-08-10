import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  const defaultDate = new Date();
  defaultDate.setHours(0, 0, 0, 0);

  await elUpdateByQueryForMigration(
    '[MIGRATION] from Synchronizers current_state to current_state_date',
    READ_INDEX_INTERNAL_OBJECTS,
    {
      script: {
        source: 'if (ctx._source.current_state == params.emptyCurrentState) {'
          + 'ctx._source.current_state_date = params.defaultDate'
          + '} else {'
          + 'ctx._source.current_state_date = ctx._source.current_state'
          + '}'
          + 'ctx._source.remove("current_state")',
        params: {
          emptyCurrentState: {},
          defaultDate
        }
      },
      query: {
        term: {
          'entity_type.keyword': {
            value: 'Sync'
          }
        }
      }
    }
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  next();
};

export const down = async (next) => {
  next();
};
