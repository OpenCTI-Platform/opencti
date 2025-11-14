import { FunctionalError } from '../../../config/errors';
import { deleteElementById, updateAttribute } from '../../../database/middleware';
import { publishUserAction } from '../../../listener/UserActionListener';
import { BUS_TOPICS } from '../../../config/conf';
import { pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { DecayExclusionRuleAddInput, EditInput, QueryDecayExclusionRulesArgs } from '../../../generated/graphql';
import { BasicStoreEntityDecayExclusionRule, ENTITY_TYPE_DECAY_EXCLUSION_RULE, StoreEntityDecayExclusionRule } from './decayExclusionRule-types';
import { createInternalObject } from '../../../domain/internalObject';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDecayExclusionRule>(context, user, id, ENTITY_TYPE_DECAY_EXCLUSION_RULE);
};
export const findDecayExclusionRulePaginated = (context: AuthContext, user: AuthUser, args: QueryDecayExclusionRulesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDecayExclusionRule>(context, user, [ENTITY_TYPE_DECAY_EXCLUSION_RULE], args);
};

export const addDecayExclusionRule = (context: AuthContext, user: AuthUser, input: DecayExclusionRuleAddInput) => {
  return createInternalObject<StoreEntityDecayExclusionRule>(context, user, input, ENTITY_TYPE_DECAY_EXCLUSION_RULE);
};
export const fieldPatchDecayExclusionRule = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const decayExclusionRule = await findById(context, user, id);

  if (!decayExclusionRule) {
    throw FunctionalError(`Decay exclusion rule ${id} cannot be found`);
  }

  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_DECAY_EXCLUSION_RULE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for decay exclusion rule \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DECAY_EXCLUSION_RULE, input }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};
export const deleteDecayExclusionRule = async (context: AuthContext, user: AuthUser, id: string) => {
  const decayExclusionRule = await findById(context, user, id);

  if (!decayExclusionRule) {
    throw FunctionalError(`Decay exclusion rule ${id} cannot be found`);
  }

  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_DECAY_EXCLUSION_RULE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes decay exclusion rule \`${deleted.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DECAY_EXCLUSION_RULE, input: deleted }
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, decayExclusionRule, user);
  return id;
};
