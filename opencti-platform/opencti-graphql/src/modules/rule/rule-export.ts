import type { RuleRuntime } from '../../types/rules';
import type { RuleImportConfiguration } from './rule-import-schema';

export const exportConfigPresetRule = (rule: Pick<RuleRuntime, 'activated'>): RuleImportConfiguration => ({ active: rule.activated === true });
