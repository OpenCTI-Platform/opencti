import { now } from '../../../utils/format';
import { FunctionalError, UnsupportedError } from '../../../config/errors';
import { deleteElementById, updateAttribute } from '../../../database/middleware';
import { publishUserAction } from '../../../listener/UserActionListener';
import { BUS_TOPICS, isFeatureEnabled } from '../../../config/conf';
import { pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { notify } from '../../../database/redis';
import type { DecayExclusionRuleAddInput, EditInput, QueryDecayExclusionRulesArgs } from '../../../generated/graphql';
import { type BasicStoreEntityDecayExclusionRule, ENTITY_TYPE_DECAY_EXCLUSION_RULE, type StoreEntityDecayExclusionRule } from './decayExclusionRule-types';
import { createInternalObject } from '../../../domain/internalObject';

const isDecayExclusionRuleEnabled = isFeatureEnabled('DECAY_EXCLUSION_RULE_ENABLED');
export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  if (!isDecayExclusionRuleEnabled) throw UnsupportedError('Feature not yet available');
  return storeLoadById<BasicStoreEntityDecayExclusionRule>(context, user, id, ENTITY_TYPE_DECAY_EXCLUSION_RULE);
};
export const findDecayExclusionRulePaginated = (context: AuthContext, user: AuthUser, args: QueryDecayExclusionRulesArgs) => {
  if (!isDecayExclusionRuleEnabled) throw UnsupportedError('Feature not yet available');
  return pageEntitiesConnection<BasicStoreEntityDecayExclusionRule>(context, user, [ENTITY_TYPE_DECAY_EXCLUSION_RULE], args);
};

export const getActiveDecayExclusionRule = async (context: AuthContext, user: AuthUser) => {
  const decayExclusionRuleEdges = await findDecayExclusionRulePaginated(context, user, {});
  return decayExclusionRuleEdges.edges.map(({ node }) => node).filter((rule) => rule.active);
};

export const checkDecayExclusionRules = async (context: AuthContext, user: AuthUser, observableType: string) => {
  const activeDecayExclusionRuleList = await getActiveDecayExclusionRule(context, user);
  const exclusionRuleList = activeDecayExclusionRuleList.filter((rule) => rule.decay_exclusion_observable_types.includes(observableType));
  const hasExclusionRuleMatching = exclusionRuleList.length > 0;
  if (!isDecayExclusionRuleEnabled) {
    return {
      exclusionRule: [],
      hasExclusionRuleMatching: false,
    };
  }
  return {
    exclusionRule: hasExclusionRuleMatching ? exclusionRuleList[0] : [],
    hasExclusionRuleMatching
  };
};

export const addDecayExclusionRule = (context: AuthContext, user: AuthUser, input: DecayExclusionRuleAddInput) => {
  if (!isDecayExclusionRuleEnabled) throw UnsupportedError('Feature not yet available');
  const defaultOps = { created_at: now() };
  const decayExclusionRuleInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntityDecayExclusionRule>(context, user, decayExclusionRuleInput, ENTITY_TYPE_DECAY_EXCLUSION_RULE);
};
export const fieldPatchDecayExclusionRule = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  if (!isDecayExclusionRuleEnabled) throw UnsupportedError('Feature not yet available');
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
  if (!isDecayExclusionRuleEnabled) throw UnsupportedError('Feature not yet available');
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
