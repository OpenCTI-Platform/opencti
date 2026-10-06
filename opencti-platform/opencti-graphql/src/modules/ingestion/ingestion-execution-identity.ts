import type { AuthContext, AuthUser } from '../../types/user';
import { ForbiddenAccess } from '../../config/errors';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { createOnTheFlyUser } from '../user/user-domain';
import { resolveUserById, resolveUserByIdFromCache, userDelete } from '../../domain/user';
import { logApp } from '../../config/conf';

// The execution identity of an ingestion can never exceed the rights of its creator.

const GENERIC_REJECTION_MESSAGE = 'You are not allowed to use this user for this ingestion';

const capabilityNames = (user: AuthUser): string[] => {
  // Capabilities are already resolved through groups and roles when the user is fully built.
  return (user.capabilities ?? []).map((capability) => capability.name);
};

// Capabilities are hierarchical: a child capability (KNOWLEDGE_KNUPDATE) also grants its parents (KNOWLEDGE),
// as in isUserHasCapability, but only exact names or descendants are matched.
const isCapabilityCoveredBy = (name: string, creatorCapabilities: string[]): boolean => {
  return creatorCapabilities.some((creatorName) => creatorName === name || creatorName.startsWith(`${name}_`));
};

const markingIds = (user: AuthUser): string[] => {
  return (user.allowed_marking ?? []).map((marking) => marking.internal_id);
};

type ConfidenceLevel = AuthUser['effective_confidence_level'];

const confidenceCeiling = (level: ConfidenceLevel, globalMax: number | null, entityType: string): number | null => {
  return (level?.overrides ?? []).find((override) => override.entity_type === entityType)?.max_confidence ?? globalMax;
};

/**
 * The target confidence ceiling must stay below the creator one, globally and for every overridden entity type,
 * because an override can raise the ceiling above the global maximum.
 */
const isConfidenceWithinCreatorLevel = (creatorUser: AuthUser, targetUser: AuthUser): boolean => {
  const creatorLevel = creatorUser.effective_confidence_level;
  const targetLevel = targetUser.effective_confidence_level;
  if (!targetLevel) {
    return true;
  }
  const creatorMax = creatorLevel?.max_confidence ?? null;
  const targetMax = targetLevel.max_confidence ?? null;
  const exceeds = (target: number | null, creator: number | null) => target !== null && (creator === null || target > creator);
  if (exceeds(targetMax, creatorMax)) {
    return false;
  }
  const entityTypes = new Set([
    ...(targetLevel.overrides ?? []).map((override) => override.entity_type),
    ...(creatorLevel?.overrides ?? []).map((override) => override.entity_type),
  ]);
  return ![...entityTypes].some((entityType) => exceeds(
    confidenceCeiling(targetLevel, targetMax, entityType),
    confidenceCeiling(creatorLevel, creatorMax, entityType),
  ));
};

/**
 * Tells whether the effective rights of the target user are included in the rights of the creator.
 */
export const isIngestionUserWithinCreatorRights = (creatorUser: AuthUser, targetUser: AuthUser): boolean => {
  // A creator with BYPASS holds every capability and marking, any identity is within its rights.
  if (isBypassUser(creatorUser)) {
    return true;
  }
  if (isBypassUser(targetUser)) {
    return false;
  }
  const creatorCapabilities = capabilityNames(creatorUser);
  if (!capabilityNames(targetUser).every((name) => isCapabilityCoveredBy(name, creatorCapabilities))) {
    return false;
  }
  const creatorMarkings = new Set(markingIds(creatorUser));
  if (!markingIds(targetUser).every((id) => creatorMarkings.has(id))) {
    return false;
  }
  return isConfidenceWithinCreatorLevel(creatorUser, targetUser);
};

/**
 * Ensures the identity used to run an ingestion does not hold more rights than the user configuring it.
 * Throws a generic ForbiddenAccess error, without disclosing the target user rights.
 */
export const validateIngestionExecutionIdentity = async (context: AuthContext, creatorUser: AuthUser, targetUserId: string | undefined | null): Promise<void> => {
  // Without an explicit identity the ingestion is executed with the platform system user, which holds every right.
  if (isEmptyField(targetUserId)) {
    if (!isBypassUser(creatorUser)) {
      throw ForbiddenAccess(GENERIC_REJECTION_MESSAGE);
    }
    return;
  }
  const targetUser = await resolveUserById(context, targetUserId as string);
  if (!targetUser) {
    throw ForbiddenAccess(GENERIC_REJECTION_MESSAGE);
  }
  if (!isIngestionUserWithinCreatorRights(creatorUser, targetUser as AuthUser)) {
    throw ForbiddenAccess(GENERIC_REJECTION_MESSAGE);
  }
};

/**
 * Creates the dedicated user of an ingestion and guarantees it does not inherit more than the creator rights.
 * The user is rolled back when the resulting rights exceed the ones of the creator.
 */
export const createIngestionAutomaticUser = async (
  context: AuthContext,
  creatorUser: AuthUser,
  input: { userName: string; serviceAccount: boolean; confidenceLevel: number | null | undefined },
) => {
  const createdUser = await createOnTheFlyUser(context, creatorUser, input);
  try {
    await validateIngestionExecutionIdentity(context, creatorUser, createdUser.id);
  } catch (error) {
    try {
      await userDelete(context, SYSTEM_USER, createdUser.id);
    } catch (deleteError) {
      logApp.error('[INGESTION] Unable to rollback the automatically created ingestion user', { cause: deleteError, id: createdUser.id });
    }
    throw error;
  }
  return createdUser;
};

/**
 * Validates the identity already stored on an ingestion. Unlike a newly chosen identity, the stored one may refer
 * to a user deleted since then: an editor holding every right still covers it and must be able to repair the feed.
 */
export const validateStoredIngestionExecutionIdentity = async (
  context: AuthContext,
  editorUser: AuthUser,
  storedIngestion: { user_id?: string | null } | undefined,
): Promise<void> => {
  if (isBypassUser(editorUser)) {
    return;
  }
  await validateIngestionExecutionIdentity(context, editorUser, storedIngestion?.user_id);
};

// Fields that neither change what is ingested nor how, editing them alone does not require the identity rights.
const EDIT_KEYS_WITHOUT_IDENTITY_CHECK = ['ingestion_running', 'name', 'description'];

/**
 * Same validation applied to edition inputs. Any edition (uri, mapper, authentication, members...) changes
 * what is executed under the ingestion identity, so the effective identity, the new one or the stored one,
 * must stay within the rights of the editing user.
 */
export const validateIngestionExecutionIdentityFromEditInputs = async (
  context: AuthContext,
  editorUser: AuthUser,
  storedIngestion: { user_id?: string | null } | undefined,
  inputs: { key: string; value: Array<string | undefined | null> }[],
): Promise<void> => {
  if (inputs.length > 0 && inputs.every((editInput) => EDIT_KEYS_WITHOUT_IDENTITY_CHECK.includes(editInput.key))) {
    return;
  }
  const userIdInput = inputs.find((editInput) => editInput.key === 'user_id');
  if (userIdInput) {
    await validateIngestionExecutionIdentity(context, editorUser, userIdInput.value?.[0]);
  } else {
    await validateStoredIngestionExecutionIdentity(context, editorUser, storedIngestion);
  }
};

interface IngestionExecutionIdentity {
  id: string;
  name?: string;
  user_id?: string | undefined;
  creator_id?: string | string[] | undefined;
}

/**
 * Defense in depth: re-checks, at execution time, that the stored identity is still covered by one of
 * the ingestion creators. Uses the platform user cache to stay cheap on the hot ingestion path.
 */
export const assertIngestionExecutionIdentityAllowed = async (context: AuthContext, ingestion: IngestionExecutionIdentity): Promise<void> => {
  // An ingestion without an explicit identity is executed with the platform system user, which holds every right.
  const targetUser = isEmptyField(ingestion.user_id) ? SYSTEM_USER : await resolveUserByIdFromCache(context, ingestion.user_id as string) as AuthUser | undefined;
  if (!targetUser) {
    throw ForbiddenAccess(GENERIC_REJECTION_MESSAGE, { id: ingestion.id });
  }
  const creatorIds = (Array.isArray(ingestion.creator_id) ? ingestion.creator_id : [ingestion.creator_id]).filter((id): id is string => isNotEmptyField(id));
  const resolvedCreators = await Promise.all(creatorIds.map((id) => resolveUserByIdFromCache(context, id) as Promise<AuthUser | undefined>));
  const creators = resolvedCreators.filter((creator): creator is AuthUser => !!creator);
  if (creators.length === 0) {
    // No creator can be resolved anymore, the rights of the identity cannot be bounded: only trace it.
    logApp.error('[INGESTION] Unable to resolve the creator of an ingestion, execution identity could not be verified', { id: ingestion.id, name: ingestion.name });
    return;
  }
  if (!creators.some((creator) => isIngestionUserWithinCreatorRights(creator, targetUser))) {
    throw ForbiddenAccess(GENERIC_REJECTION_MESSAGE, { id: ingestion.id });
  }
};
