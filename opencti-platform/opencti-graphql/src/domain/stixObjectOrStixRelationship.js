import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (context, user, id) => {
  return elLoadById(context, user, id, null, READ_PLATFORM_INDICES);
};
