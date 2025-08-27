import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR } from './pir-types';
import { getEntitiesMapFromCache } from '../../database/cache';
import { FunctionalError } from '../../config/errors';
import { isUserCanAccessStoreElement } from '../../utils/access';

/**
 * Helper function to check a user has access to a pir
 * and return the pir
 */
export const getPirWithAccessCheck = async (context: AuthContext, user: AuthUser, pirId?: string | null) => {
  // check EE
  await checkEnterpriseEdition(context);
  // check user has access to the PIR
  if (!pirId) {
    throw FunctionalError('No Pir ID provided');
  }
  const pirs = await getEntitiesMapFromCache<BasicStoreEntityPir>(context, user, ENTITY_TYPE_PIR);
  const pir = pirs.get(pirId);
  if (!pir) {
    throw FunctionalError('No PIR found', { pirId });
  }
  await isUserCanAccessStoreElement(context, user, pir);
  return pir;
};
