import type { Rule } from 'eslint';
import classesRules from './rules/classes-rule.ts';
import noDeprecatedComponents from './rules/no-deprecated-components.ts';
import noFragmentRefAnchor from './rules/no-fragment-ref-anchor.ts';
import noReplacedComponents from './rules/no-replaced-components.ts';

const rules: Record<string, Rule.RuleModule> = {
  'classes-rule': classesRules,
  'no-deprecated-components': noDeprecatedComponents,
  'no-fragment-ref-anchor': noFragmentRefAnchor,
  'no-replaced-components': noReplacedComponents,
};

export default rules;
