import { getRules, RULES_DECLARATION } from '../../../domain/rules';
import type { RuleRuntime } from '../../../types/rules';
import { exportConfigPresetRule } from '../../rule/rule-export';
import { importConfigPresetRule, isRuleEngineEnabled } from '../../rule/rule-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter, ConfigPresetImportPlan } from '../import/configPreset-import-types';
import { automationRulesGroup, staticFamily, toAppliedStatus, toComputedItem, toIsEnabled } from './common-configPreset-registry';

export const RULE_ENGINE_FAMILY_ID = 'ruleEngine';

const toRuleItem = (rule: RuleRuntime): ConfigPresetItemDefinition => ({
  id: rule.id,
  label: rule.name,
  translatable: true,
  isEnabled: rule.activated === true,
  exporter: async () => exportConfigPresetRule(rule),
});

const engineStates = new WeakMap<ConfigPresetImportPlan, Promise<boolean>>();
const isEngineEnabledFor = (plan: ConfigPresetImportPlan) => {
  if (!engineStates.has(plan)) {
    engineStates.set(plan, isRuleEngineEnabled());
  }
  return engineStates.get(plan) as Promise<boolean>;
};

const ruleEngineImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const rule = RULES_DECLARATION.find(({ id }) => id === item.id);
    const label = rule ? { label: rule.name, translatable: true } : { label: item.id, translatable: false };
    const options = { mode, dryRun: true, isRuleEngineEnabled: await isEngineEnabledFor(plan) };
    const result = await importConfigPresetRule(context, user, item.id, item.configuration, options);
    return { ...toComputedItem(label, result), isEnabled: toIsEnabled(result.configuration?.active) };
  },
  // The write reads the state of the engine again: it may have been disabled since the preview
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importConfigPresetRule(context, user, item.id, item.configuration, { mode }), computed);
  },
};

export const ruleEngineFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: RULE_ENGINE_FAMILY_ID,
    label: 'Rule engine',
    description: 'Activation of the inference rules',
    group: automationRulesGroup,
    directory: 'automation_rules/rule_engine',
  }, async (context, user) => (await getRules(context, user)).map(toRuleItem)),
  importer: ruleEngineImporter,
};
