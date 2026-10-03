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
  // The generic trigger creation silently falls back to the creator when several recipients are given
  if (input.recipients && input.recipients.length > 1) {
    throw ValidationError('A change digest has a single recipient: a user, a group or an organization', 'recipients', { count: input.recipients.length });
  }
  // The filter set is resolved and validated once: a saved filter is copied with the entity types of its list,
  // so the digest keeps its scope if the saved filter changes and its recipients do not need access to it
  const now = new Date().toISOString();
  const scope = await resolveLandscapeScope(context, user, {
    filters: input.filters,
    saved_filter_id: input.saved_filter_id,
    entity_types: input.scope_entity_types,
    from: now,
    to: now,
  });
  const { saved_filter_id: _savedFilterId, ...triggerFields } = input;
  const triggerInput = {
    ...triggerFields,
    filters: scope.filters ? JSON.stringify(scope.filters) : null,
    scope_entity_types: scope.entityTypes,
    instance_trigger: false,
  };
  return addTrigger(context, user, triggerInput as unknown as TriggerDigestAddInput, TRIGGER_TYPE_CHANGE_DIGEST as TriggerType);
};
