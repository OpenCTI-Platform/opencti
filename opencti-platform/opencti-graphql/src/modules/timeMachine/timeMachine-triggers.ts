import { ValidationError } from '../../config/errors';
import { addTrigger } from '../notification/notification-domain';
import type { TriggerChangeDigestAddInput, TriggerDigestAddInput, TriggerType } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { resolveLandscapeScope } from './landscapeDiff-domain';
import { TRIGGER_TYPE_CHANGE_DIGEST } from './timeMachine-changeDigest';

/**
 * Create a change digest: a knowledge digest trigger sending, at each period, the landscape diff
 * of its filter set over the period, computed with the rights of each recipient.
 */
export const addChangeDigestTrigger = async (context: AuthContext, user: AuthUser, input: TriggerChangeDigestAddInput) => {
  if (!input.notifiers || input.notifiers.length === 0) {
    throw ValidationError('A change digest needs at least one notifier', 'notifiers');
  }
  // Validates the filters and the entity types of the filter set
  const now = new Date().toISOString();
  await resolveLandscapeScope(context, user, { filters: input.filters, entity_types: input.scope_entity_types, from: now, to: now });
  const triggerInput = { ...input, instance_trigger: false };
  return addTrigger(context, user, triggerInput as unknown as TriggerDigestAddInput, TRIGGER_TYPE_CHANGE_DIGEST as TriggerType);
};
