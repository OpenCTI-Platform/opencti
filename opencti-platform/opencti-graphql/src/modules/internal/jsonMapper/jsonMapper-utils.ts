import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntityJsonMapper } from './jsonMapper-types';

export const getJsonMapperErrorMessage = async (_context: AuthContext, _user: AuthUser, _jsonMapper: BasicStoreEntityJsonMapper) => {
  try {
    return null; // no error
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unknown error';
  }
};
