import { getRules, RULES_DECLARATION } from '../../../domain/rules';
import type { RuleRuntime } from '../../../types/rules';
import { exportConfigPresetRule } from '../../rule/rule-export';
import { importConfigPresetRule } from '../../rule/rule-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { automationRulesGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const RULE_ENGINE_FAMILY_ID = 'ruleEngine';

const toRuleItem = (rule: RuleRuntime): ConfigPresetItemDefinition => ({
  id: rule.id,
  label: rule.name,
  translatable: true,
  isEnabled: rule.activated === true,
  exporter: async () => exportConfigPresetRule(rule),
});

const toIsEnabled = (value: unknown) => (typeof value === 'boolean' ? value : null);

const ruleEngineImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const rule = RULES_DECLARATION.find(({ id }) => id === item.id);
    const label = rule ? { label: rule.name, translatable: true } : { label: item.id, translatable: false };
    const result = await importConfigPresetRule(context, user, item.id, item.configuration, { mode, dryRun: true });
    return { ...toComputedItem(label, result), isEnabled: toIsEnabled(result.configuration?.active) };
  },
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
