import { elLoadByIds } from '../database/elasticSearch';
import { READ_PLATFORM_INDICES } from '../database/utils';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (user, id) => elLoadByIds(user, id, null, READ_PLATFORM_INDICES);
