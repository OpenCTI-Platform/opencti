import type { Rule } from 'eslint';
import classesRules from './rules/classes-rule.ts';
import noDeprecatedComponents from './rules/no-deprecated-components.ts';
import noReplacedComponents from './rules/no-replaced-components.ts';

const rules: Record<string, Rule.RuleModule> = {
  'classes-rule': classesRules,
  'no-deprecated-components': noDeprecatedComponents,
  'no-replaced-components': noReplacedComponents,
};

export default rules;
