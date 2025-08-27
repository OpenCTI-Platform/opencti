import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_PIR } from './pir-types';
import { getEntityFromIdFromCache } from '../../database/cache';
import { FunctionalError } from '../../config/errors';

/**
 * Helper function to check a user has access to a pir functionnalities
 */
export const checkEEAndPirAccess = async (context: AuthContext, user: AuthUser, pirId?: string | null) => {
  // check EE
  await checkEnterpriseEdition(context);
  // check user has access to the PIR
  if (!pirId) {
    throw FunctionalError('No Pir ID provided');
  }
  const pir = await getEntityFromIdFromCache(context, user, pirId, ENTITY_TYPE_PIR);
  if (!pir) {
    throw FunctionalError('No PIR found', { pirId });
  }
};
