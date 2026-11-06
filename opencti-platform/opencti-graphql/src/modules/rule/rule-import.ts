import { isModuleActivated } from '../../database/cluster-module';
import { getRule, setRuleActivation } from '../../domain/rules';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportValidationReason } from '../configImport/configImport-utils';
import { type RuleImportConfiguration, ruleImportSchema } from './rule-import-schema';

export type RuleImportCode = 'invalid' | 'unknown_rule' | 'not_overwrite' | 'unchanged';

export type RuleImportResult = ConfigImportResult<RuleImportConfiguration, RuleImportCode>;

export const RULE_ACTIVATION_SCAN_REASON = 'Activating the rule starts a scan of the knowledge base';
export const RULE_DEACTIVATION_SCAN_REASON = 'Deactivating the rule starts a scan of the knowledge base';

export const importConfigPresetRule = async (
  context: AuthContext,
  user: AuthUser,
  ruleId: string,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<RuleImportResult> => {
  const rule = await getRule(context, user, ruleId);
  const parsed = ruleImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return { status: 'failed', code: 'invalid', reason: configImportValidationReason(parsed.error), exists: !!rule };
  }
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
  if (!dryRun) {
    await setRuleActivation(context, user, ruleId, active);
  }
  const scans = await isModuleActivated('RULE_ENGINE');
  return {
    status: 'overwritten',
    exists: true,
    configuration: parsed.data,
    ...(scans ? { reason: active ? RULE_ACTIVATION_SCAN_REASON : RULE_DEACTIVATION_SCAN_REASON } : {}),
  };
};
