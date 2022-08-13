import { DatabaseError } from '../config/errors';
import { elRawDeleteByQuery } from '../database/engine';
import { READ_INDEX_HISTORY } from '../database/utils';

export const up = async (next) => {
  const query = {
    match: { entity_type: 'Work' },
  };
  // Clean all current platform works
  await elRawDeleteByQuery({
    index: READ_INDEX_HISTORY,
    refresh: true,
    body: { query },
  }).catch((err) => {
    throw DatabaseError('Error cleaning the work', { error: err });
  });
  next();
};

export const down = async (next) => {
  // Nothing to do.
  next();
};
