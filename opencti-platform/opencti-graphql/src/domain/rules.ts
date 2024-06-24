import type { RuleDefinition, RuleRuntime } from '../types/rules';
import type { BasicRuleEntity } from '../types/store';
import { ENTITY_TYPE_RULE, ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import AttributedToAttributedRule from '../rules/attributed-to-attributed/AttributedToAttributedRule';
import AttributionTargetsRule from '../rules/attribution-targets/AttributionTargetsRule';
import AttributionUseRule from '../rules/attribution-use/AttributionUseRule';
import RuleLocalizationOfTargets from '../rules/localization-of-targets/LocalizationOfTargetsRule';
import LocatedAtLocatedRule from '../rules/located-at-located/LocatedAtLocatedRule';
import LocationTargetsRule from '../rules/location-targets/LocationTargetsRule';
import ParticipateToParts from '../rules/participate-to-parts/ParticipateToPartsRule';
import RuleObservableRelatedObservable from '../rules/observable-related/ObservableRelatedRule';
import RuleObserveSighting from '../rules/observed-sighting/ObserveSightingRule';
import PartOfPartRule from '../rules/part-of-part/PartOfPartRule';
import PartOfTargetsRule from '../rules/part-of-targets/PartOfTargetsRule';
import RuleSightingIncident from '../rules/sighting-incident/SightingIncidentRule';
import RelatedToRelatedRule from '../rules/related-to-related/RelatedToRelatedRule';
import IndicateSightedRule from '../rules/indicate-sighted/IndicateSightedRule';
import SightingObservableRule from '../rules/sighting-observable/SightingObservableRule';
import SightingIndicatorRule from '../rules/sighting-indicator/SightingIndicatorRule';
import ReportRefIdentityPartOfRule from '../rules/report-refs-identity-part-of/ReportRefIdentityPartOfRule';
import ReportRefsIndicatorBasedOnRule from '../rules/report-refs-indicator-based-on/ReportRefIndicatorBasedOnRule';
import ReportRefObservableBasedOnRule from '../rules/report-refs-observable-based-on/ReportRefObservableBasedOnRule';
import ReportRefsLocationLocatedAtRule from '../rules/report-refs-location-located-at/ReportRefLocationLocatedAtRule';
import ParentTechniqueUseRule from '../rules/parent-technique-use/ParentTechniqueUseRule';
import { BUS_TOPICS, DEV_MODE } from '../config/conf';
import type { AuthContext, AuthUser } from '../types/user';
import { isEmptyField } from '../database/utils';
import { UnsupportedError } from '../config/errors';
import { createEntity } from '../database/middleware';
import { createRuleTask, deleteRuleTasks } from './backgroundTask';
import { notify } from '../database/redis';
import { getEntitiesListFromCache } from '../database/cache';
import { isModuleActivated } from './settings';
import { publishUserAction } from '../listener/UserActionListener';

export const RULES_DECLARATION: Array<RuleRuntime> = [
  AttributedToAttributedRule,
  AttributionTargetsRule,
  IndicateSightedRule,
  AttributionUseRule,
  RuleLocalizationOfTargets,
  LocatedAtLocatedRule,
  LocationTargetsRule,
  ParticipateToParts,
  RuleObservableRelatedObservable,
  RuleObserveSighting,
  PartOfPartRule,
  PartOfTargetsRule,
  RuleSightingIncident,
  SightingObservableRule,
  SightingIndicatorRule,
  ReportRefIdentityPartOfRule,
  ReportRefsIndicatorBasedOnRule,
  ReportRefObservableBasedOnRule,
  ReportRefsLocationLocatedAtRule,
  ParentTechniqueUseRule
];
if (DEV_MODE) {
  RULES_DECLARATION.push(RelatedToRelatedRule);
}

export const getRules = async (context: AuthContext, user: AuthUser): Promise<Array<RuleRuntime>> => {
  const rules = await getEntitiesListFromCache<BasicRuleEntity>(context, user, ENTITY_TYPE_RULE);
  return RULES_DECLARATION.map((def: RuleRuntime) => {
    const esRule = rules.find((e) => e.internal_id === def.id);
    const isActivated = esRule?.active === true;
    return { ...def, activated: isActivated };
  });
};

export const getActivatedRules = async (context: AuthContext, user: AuthUser): Promise<Array<RuleRuntime>> => {
  const rules = await getRules(context, user);
  return rules.filter((r) => r.activated);
};

export const getRule = async (context: AuthContext, user: AuthUser, id: string): Promise<RuleDefinition | undefined> => {
  const rules = await getRules(context, user);
  return rules.find((e) => e.id === id);
};

export const setRuleActivation = async (context: AuthContext, user: AuthUser, ruleId: string, active: boolean): Promise<RuleDefinition | undefined> => {
  const resolvedRule = await getRule(context, user, ruleId);
  if (isEmptyField(resolvedRule)) {
    throw UnsupportedError(`Cant ${active ? 'enable' : 'disable'} undefined rule ${ruleId}`);
  }
  // Update the rule via upsert
  const rule = await createEntity(context, user, { internal_id: ruleId, active, update: true }, ENTITY_TYPE_RULE);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ENTITY_TYPE_RULE].EDIT_TOPIC, rule, user);
  // Refresh the activated rules
  const isRuleEngineActivated = await isModuleActivated('RULE_ENGINE');
  if (isRuleEngineActivated) {
    await deleteRuleTasks(context, user, ruleId);
    await createRuleTask(context, user, resolvedRule, { rule: ruleId, enable: active });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `${active ? 'activates' : 'deactivates'} rule \`${resolvedRule?.name}\``,
    context_data: { id: ruleId, entity_type: ENTITY_TYPE_SETTINGS, input: { id: ruleId, active } }
  });
  return getRule(context, user, ruleId);
};
