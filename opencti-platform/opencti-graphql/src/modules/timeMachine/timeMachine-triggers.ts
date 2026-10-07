import { ValidationError } from '../../config/errors';
import { addTrigger, triggerEdit, triggerGet } from '../notification/notification-domain';
import type { BasicStoreEntityTrigger } from '../notification/notification-types';
import { EditOperation, type TriggerChangeDigestAddInput, type TriggerDigestAddInput, type TriggerType } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import type { InternalEditInput } from '../../types/store';
import { authorizedMembers } from '../../schema/attribute-definition';
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

const editedValues = (current: string[], items: InternalEditInput[]) => items.reduce((values, item) => {
  const value = (item.value ?? []).filter((entry): entry is string => typeof entry === 'string');
  if (item.operation === EditOperation.Add) return [...new Set([...values, ...value])];
  if (item.operation === EditOperation.Remove) return values.filter((entry) => !value.includes(entry));
  return value;
}, current);

/**
 * Edit of a knowledge trigger. A change digest keeps the rules of its creation: at least one notifier, a filter
 * set validated and stored with its entity types, and the single recipient authorized at creation (delivery reads it
 * from the members of the trigger), so an edit cannot leave a digest that fails at each period, that can never be
 * delivered or that is sent to someone else than the recipient it reports.
 */
export const triggerKnowledgeEdit = async (context: AuthContext, user: AuthUser, triggerId: string, input: InternalEditInput[]) => {
  const trigger = await triggerGet(context, user, triggerId) as BasicStoreEntityTrigger & { scope_entity_types?: string[] | null };
  if (trigger?.trigger_type !== TRIGGER_TYPE_CHANGE_DIGEST) {
    return triggerEdit(context, user, triggerId, input);
  }
  const recipientsItem = input.find((item) => item.key === 'recipients' || item.key === authorizedMembers.name);
  if (recipientsItem) {
    throw ValidationError('The recipient of a change digest is set at its creation: create another change digest for another recipient', recipientsItem.key);
  }
  const notifiersItems = input.filter((item) => item.key === 'notifiers');
  if (notifiersItems.length > 0 && editedValues(trigger.notifiers ?? [], notifiersItems).length === 0) {
    throw ValidationError('A change digest needs at least one notifier', 'notifiers');
  }
  const filtersItems = input.filter((item) => item.key === 'filters');
  const entityTypesItems = input.filter((item) => item.key === 'scope_entity_types');
  if (filtersItems.length === 0 && entityTypesItems.length === 0) {
    return triggerEdit(context, user, triggerId, input);
  }
  const editedFilters = filtersItems.length > 0 ? filtersItems[filtersItems.length - 1].value?.[0] ?? null : trigger.filters;
  const filters = editedFilters && typeof editedFilters !== 'string' ? JSON.stringify(editedFilters) : editedFilters;
  const entityTypes = entityTypesItems.length > 0 ? editedValues(trigger.scope_entity_types ?? [], entityTypesItems) : trigger.scope_entity_types;
  const now = new Date().toISOString();
  const scope = await resolveLandscapeScope(context, user, { filters, entity_types: entityTypes, from: now, to: now });
  const scopeInput: InternalEditInput[] = [
    { key: 'filters', value: [scope.filters ? JSON.stringify(scope.filters) : null] },
    { key: 'scope_entity_types', value: scope.entityTypes ?? [] },
  ];
  const otherInput = input.filter((item) => item.key !== 'filters' && item.key !== 'scope_entity_types');
  return triggerEdit(context, user, triggerId, [...otherInput, ...scopeInput]);
};
