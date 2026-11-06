import { isModuleActivated } from '../../database/cluster-module';
import { getRule, setRuleActivation } from '../../domain/rules';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportValidationReason } from '../configImport/configImport-utils';
import { CONFIG_IMPORT_SENSITIVE_REASON, isConfigImportSensitiveChangeAllowed } from '../user/sensitive-config-import';
import { type RuleImportConfiguration, ruleImportSchema } from './rule-import-schema';

export type RuleImportCode = 'invalid' | 'unknown_rule' | 'not_overwrite' | 'unchanged' | 'sensitive_config' | 'engine_disabled';

export type RuleImportResult = ConfigImportResult<RuleImportConfiguration, RuleImportCode>;

export interface RuleImportOptions extends ConfigImportOptions {
  isRuleEngineEnabled?: boolean;
}

export const RULE_ACTIVATION_SCAN_REASON = 'Activating the rule starts a scan of the knowledge base';
export const RULE_DEACTIVATION_SCAN_REASON = 'Deactivating the rule starts a scan that deletes what it inferred';
export const RULE_ENGINE_DISABLED_REASON = 'The rule engine is disabled';

export const isRuleEngineEnabled = () => isModuleActivated('RULE_ENGINE');

export const importConfigPresetRule = async (
  context: AuthContext,
  user: AuthUser,
  ruleId: string,
  configuration: unknown,
  { mode, dryRun = false, isRuleEngineEnabled: engineEnabled }: RuleImportOptions,
): Promise<RuleImportResult> => {
  const parsed = ruleImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return { status: 'failed', code: 'invalid', reason: configImportValidationReason(parsed.error), exists: false };
  }
  const rule = await getRule(context, user, ruleId);
  if (!rule) {
    return { status: 'failed', code: 'unknown_rule', reason: 'Unknown rule', exists: false, configuration: parsed.data };
  }
  if (mode !== ConfigImportMode.Overwrite) {
    return { status: 'skipped', code: 'not_overwrite', reason: 'Already exists', exists: true, configuration: parsed.data };
  }
  const { active } = parsed.data;
  if ((rule.activated === true) === active) {
    return { status: 'skipped', code: 'unchanged', reason: CONFIG_IMPORT_UNCHANGED_REASON, exists: true, configuration: parsed.data };
  }
  if (!(await isConfigImportSensitiveChangeAllowed(context, user, 'rules'))) {
    return { status: 'failed', code: 'sensitive_config', reason: CONFIG_IMPORT_SENSITIVE_REASON, exists: true, configuration: parsed.data };
  }
  // As in the rules screen: a rule switched while the engine is off would never be applied to the existing knowledge
  if (!(engineEnabled ?? await isRuleEngineEnabled())) {
    return { status: 'skipped', code: 'engine_disabled', reason: RULE_ENGINE_DISABLED_REASON, exists: true, configuration: parsed.data };
  }
  if (!dryRun) {
    await setRuleActivation(context, user, ruleId, active);
  }
  return {
    status: 'overwritten',
    exists: true,
    configuration: parsed.data,
    reason: active ? RULE_ACTIVATION_SCAN_REASON : RULE_DEACTIVATION_SCAN_REASON,
  };
};
