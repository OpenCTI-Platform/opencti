import { DatabaseError } from '../config/errors';
import { el, INDEX_HISTORY } from '../database/elasticSearch';

export const up = async (next) => {
  const query = {
    match: { entity_type: 'Work' },
  };
  // Clean all current platform works
  await el
    .deleteByQuery({
      index: INDEX_HISTORY,
      refresh: true,
      body: { query },
    })
    .catch((err) => {
      throw DatabaseError('Error cleaning the work', { error: err });
    });
  next();
};

export const down = async (next) => {
  // Nothing to do.
  next();
};
