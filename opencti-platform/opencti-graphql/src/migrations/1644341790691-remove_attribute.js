import { elRawDeleteByQuery } from '../database/engine';
import { READ_ENTITIES_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  const query = {
    match: { entity_type: 'Attribute' },
  };
  // Clean all current platform attributes
  await elRawDeleteByQuery({
    index: READ_ENTITIES_INDICES,
    refresh: true,
    body: { query },
  }).catch((err) => {
    throw DatabaseError('Error cleaning the attribute', { error: err });
  });
  next();
};

export const down = async (next) => {
  next();
};
