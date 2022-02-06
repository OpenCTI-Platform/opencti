import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (user, id) => elLoadById(user, id, null, READ_PLATFORM_INDICES);
