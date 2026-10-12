import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { AccessOperation, isUserHasCapability, KNOWLEDGE_KNENRICHMENT, validateUserAccessOperation } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';

const INVESTIGATION_UPDATE_CAPABILITY = 'INVESTIGATION_INUPDATE';

/**
 * Tagging an enrichment with an investigation requires to be allowed to edit that investigation.
 * A non member of a restricted investigation cannot load it, so it is reported as not found.
 * Capabilities are checked before the load so that the error does not reveal whether the id exists.
 */
export const validateEnrichmentInvestigation = async (
  context: AuthContext,
  user: AuthUser,
  investigationId: string,
  opts: { checkEnrichmentCapability?: boolean } = {},
) => {
  if ((opts.checkEnrichmentCapability && !isUserHasCapability(user, KNOWLEDGE_KNENRICHMENT)) || !isUserHasCapability(user, INVESTIGATION_UPDATE_CAPABILITY)) {
    throw ForbiddenAccess();
  }
  const investigation = await storeLoadById<BasicStoreEntityWorkspace>(context, user, investigationId, ENTITY_TYPE_WORKSPACE);
  if (!investigation || investigation.type !== 'investigation') {
    throw FunctionalError('Investigation not found', { investigationId });
  }
  if (!validateUserAccessOperation(user, investigation, AccessOperation.EDIT)) {
    throw ForbiddenAccess();
  }
  return investigation;
};
