import type { RuleRuntime, RuleDefinition } from '../types/rules';
import type { BasicRuleEntity, BasicTaskEntity } from '../types/store';
import { ENTITY_TYPE_RULE, ENTITY_TYPE_TASK } from '../schema/internalObject';
import AttributedToAttributedRule from '../rules/attributed-to-attributed/AttributedToAttributedRule';
import AttributionTargetsRule from '../rules/attribution-targets/AttributionTargetsRule';
import AttributionUseRule from '../rules/attribution-use/AttributionUseRule';
import RuleLocalizationOfTargets from '../rules/localization-of-targets/LocalizationOfTargetsRule';
import LocatedAtLocatedRule from '../rules/located-at-located/LocatedAtLocatedRule';
import LocationTargetsRule from '../rules/location-targets/LocationTargetsRule';
import RuleObservableRelatedObservable from '../rules/observable-related/ObservableRelatedRule';
import RuleObserveSighting from '../rules/observed-sighting/ObserveSightingRule';
import PartOfPartRule from '../rules/part-of-part/PartOfPartRule';
import PartOfTargetsRule from '../rules/part-of-targets/PartOfTargetsRule';
import RuleSightingIncident from '../rules/sighting-incident/SightingIncidentRule';
import RelatedToRelatedRule from '../rules/related-to-related/RelatedToRelatedRule';
import IndicateSightedRule from '../rules/indicate-sighted/IndicateSightedRule';
import SightingObservableRule from '../rules/sighting-observable/SightingObservableRule';
import SightingIndicatorRule from '../rules/sighting-indicator/SightingIndicatorRule';
import { BUS_TOPICS, DEV_MODE, ENABLED_RULE_ENGINE } from '../config/conf';
import { getEntitiesFromCache } from '../manager/cacheManager';
import type { AuthUser } from '../types/user';
import { isEmptyField } from '../database/utils';
import { UnsupportedError } from '../config/errors';
import { createEntity } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { createRuleTask, deleteTask } from './task';
import { notify } from '../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';

export const RULES_DECLARATION: Array<RuleRuntime> = [
  AttributedToAttributedRule,
  AttributionTargetsRule,
  IndicateSightedRule,
  AttributionUseRule,
  RuleLocalizationOfTargets,
  LocatedAtLocatedRule,
  LocationTargetsRule,
  RuleObservableRelatedObservable,
  RuleObserveSighting,
  PartOfPartRule,
  PartOfTargetsRule,
  RuleSightingIncident,
  SightingObservableRule,
  SightingIndicatorRule,
];
if (DEV_MODE) {
  RULES_DECLARATION.push(RelatedToRelatedRule);
}

export const getRules = async (): Promise<Array<RuleRuntime>> => {
  const rules = await getEntitiesFromCache<BasicRuleEntity>(ENTITY_TYPE_RULE);
  return RULES_DECLARATION.map((def: RuleRuntime) => {
    const esRule = rules.find((e) => e.internal_id === def.id);
    const isActivated = esRule?.active === true;
    return { ...def, activated: isActivated };
  });
};

export const getActivatedRules = async (): Promise<Array<RuleRuntime>> => {
  const rules = await getRules();
  return rules.filter((r) => r.activated);
};

export const getRule = async (id: string): Promise<RuleDefinition | undefined> => {
  const rules = await getRules();
  return rules.find((e) => e.id === id);
};

export const setRuleActivation = async (user: AuthUser, ruleId: string, active: boolean): Promise<RuleDefinition | undefined> => {
  const resolvedRule = await getRule(ruleId);
  if (isEmptyField(resolvedRule)) {
    throw UnsupportedError(`Cant ${active ? 'enable' : 'disable'} undefined rule ${ruleId}`);
  }
  // Update the rule
  const rule = await createEntity(user, { internal_id: ruleId, active, update: true }, ENTITY_TYPE_RULE);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, rule, user);
  // Refresh the activated rules
  // activatedRules = await getActivatedRules();
  if (ENABLED_RULE_ENGINE) {
    const tasksFilters = [{ key: 'type', values: ['RULE'] }, { key: 'rule', values: [ruleId] }];
    const args = { filters: tasksFilters, connectionFormat: false };
    const tasks = await listEntities<BasicTaskEntity>(user, [ENTITY_TYPE_TASK], args);
    await Promise.all(tasks.map((t) => deleteTask(user, t.internal_id)));
    await createRuleTask(user, resolvedRule, { rule: ruleId, enable: active });
  }
  return getRule(ruleId);
};
