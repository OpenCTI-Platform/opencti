import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreObject } from '../../types/store';
import { internalFindByIds } from '../../database/middleware-loader';

// Elements by ids (internal ids, standard ids or stix ids) as an array, restricted to what the user can access
export const findByIds = async <T extends BasicStoreObject>(
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  args?: { type?: string | string[] },
): Promise<T[]> => {
  if (ids.length === 0) {
    return [];
  }
  return (await internalFindByIds<T>(context, user, ids, args)) as T[];
};
