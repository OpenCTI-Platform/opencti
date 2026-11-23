// Converts the "pick a PIR type, then pick preset rules" choices into the requirement draft,
// and provides default names, validation and the read-only query chips shown for a rule.
import {
  emptyCondition,
  emptyCriterion,
  emptyDraft,
  emptyGroup,
  newId,
  type IrConditionDraft,
  type IrCriterionDraft,
  type IrDirection,
  type IrDraft,
  type IrEntityOption,
  type IrGroupDraft,
  type IrLinkDraft,
  type IrPriority,
} from './irConfigTypes';
import { getRule, IR_PIR_TYPES, type IrPirType, type IrPresetRule } from './irPresetRules';

export interface IrPresetValue {
  entities: IrEntityOption[]; // picked entities, and labels as { value: labelId, label: labelValue, type: 'Label' }
  types: string[]; // the "any ..." choices and container types
  terms: string[]; // vocabulary keys, keywords and text values
  number: number | null;
}

export interface IrRuleInstance {
  id: string;
  ruleKey: string;
  value: IrPresetValue;
}

export type IrPresetItem =
  | { id: string; kind: 'rule'; name: string; rule: IrRuleInstance }
  | { id: string; kind: 'group'; name: string; rules: IrRuleInstance[] }
  | { id: string; kind: 'custom'; name: string; filters: string | null };

export interface IrPresetGeneral {
  name: string;
  question: string;
  description: string;
  priority: IrPriority;
}

type Translate = (s: string) => string;

export const emptyValue = (): IrPresetValue => ({ entities: [], types: [], terms: [], number: null });

// region names and values
const MAX_NAMED_VALUES = 3;

const valueLabels = (value: IrPresetValue, t: Translate): string[] => [
  ...value.entities.map((e) => e.label),
  ...value.types.map((type) => `${t('any')} ${t(type)}`),
  ...value.terms,
  ...(value.number !== null ? [String(value.number)] : []),
];

const hasValue = (value: IrPresetValue) => valueLabels(value, (s) => s).length > 0;

const namedValues = (value: IrPresetValue, t: Translate): string => {
  const labels = valueLabels(value, t);
  const shown = labels.slice(0, MAX_NAMED_VALUES).join(', ');
  return labels.length > MAX_NAMED_VALUES ? `${shown} +${labels.length - MAX_NAMED_VALUES} more` : shown;
};

const subjectOf = (pirType: IrPirType, t: Translate) => t(IR_PIR_TYPES.find((p) => p.key === pirType)?.subject ?? 'Entities');

export const defaultRuleName = (pirType: IrPirType, rule: IrRuleInstance, t: Translate): string => {
  const def = getRule(rule.ruleKey);
  const subject = subjectOf(pirType, t);
  const verb = t(def.verb);
  if (def.value === 'none') return `${subject} ${verb}`;
  const values = namedValues(rule.value, t);
  if (verb === ':') return `${subject}: ${values}`;
  if (verb.includes('{v}')) return `${subject} ${verb.replace('{v}', values)}`;
  return `${subject} ${verb} ${values}`;
};

export const defaultItemName = (pirType: IrPirType, item: IrPresetItem, t: Translate): string => {
  if (item.kind === 'rule') return defaultRuleName(pirType, item.rule, t);
  if (item.kind === 'group') return item.rules.length > 0 ? defaultRuleName(pirType, item.rules[0], t) : subjectOf(pirType, t);
  return `${subjectOf(pirType, t)} ${t('matching custom filters')}`;
};
// endregion

// region validation
export const validatePresetItems = (items: IrPresetItem[]): { itemId: string; ruleId?: string; message: string }[] => {
  if (items.length === 0) return [{ itemId: '', message: 'Add at least one rule' }];
  const errors: { itemId: string; ruleId?: string; message: string }[] = [];
  const checkRule = (itemId: string, rule: IrRuleInstance) => {
    if (getRule(rule.ruleKey).value !== 'none' && !hasValue(rule.value)) errors.push({ itemId, ruleId: rule.id, message: 'Add a value' });
  };
  items.forEach((item) => {
    if (item.kind === 'rule') checkRule(item.id, item.rule);
    else if (item.kind === 'group') {
      if (item.rules.length === 0) errors.push({ itemId: item.id, message: 'Add at least one rule' });
      item.rules.forEach((rule) => checkRule(item.id, rule));
    } else if (!item.filters) errors.push({ itemId: item.id, message: 'Add filters' });
  });
  return errors;
};
// endregion

// region query chips
const FILTER_KEY_LABELS: Record<string, string> = {
  objectLabel: 'Label',
  malware_types: 'Malware type',
  sophistication: 'Sophistication',
  resource_level: 'Resource level',
  capabilities: 'Capability',
  x_opencti_cvss_base_score: 'CVSS score',
  x_opencti_epss_score: 'EPSS score',
  account_type: 'Account type',
};

// Rules reading as "<flagged> -relationship-> <anchor>": the chips show the relationship and both sides
const relationshipOf = (def: IrPresetRule): { relationships: string[]; direction: IrDirection } | null => {
  const { build } = def;
  switch (build.kind) {
    case 'linked':
    case 'linkedViaFilter':
      return { relationships: build.relationships, direction: build.direction };
    case 'container':
    case 'containerFixed':
      return { relationships: ['object'], direction: 'outgoing' };
    case 'indicated':
      return { relationships: ['indicates'], direction: 'outgoing' };
    default:
      return null;
  }
};

const filterKeyLabel = (def: IrPresetRule): string => {
  const { build } = def;
  switch (build.kind) {
    case 'entityFilter': return FILTER_KEY_LABELS[build.key] ?? build.key;
    case 'motivation': return 'Motivation';
    case 'keywords': return 'Keyword';
    case 'domains': return 'Domain';
    case 'oneOf': return 'Entity';
    default: return def.sentence;
  }
};

export const presetQueryChips = (rule: IrRuleInstance, flags: string[], t: Translate): { key: string; values: string; fromUser: boolean }[] => {
  const def = getRule(rule.ruleKey);
  const flagged = flags.join(', ');
  const values = valueLabels(rule.value, t).join(', ');
  const userChips = (key: string) => (def.value === 'none' ? [] : [{ key: t(key), values, fromUser: true }]);
  const relation = relationshipOf(def);
  if (relation) {
    const flaggedIsSource = relation.direction === 'incoming';
    return [
      { key: t('Relationship type'), values: relation.relationships.join(', '), fromUser: false },
      { key: t(flaggedIsSource ? 'Source type' : 'Target type'), values: flagged, fromUser: false },
      ...userChips(flaggedIsSource ? 'Target' : 'Source'),
    ];
  }
  return [
    { key: t('Entity type'), values: flagged, fromUser: false },
    ...userChips(filterKeyLabel(def)),
  ];
};
// endregion

// region conversion to the draft
type Filter = { key: string[]; values: string[]; operator: string; mode: 'or' };
type FilterGroupInput = { mode: 'and' | 'or'; filters: Filter[]; filterGroups: FilterGroupInput[] };

const filter = (key: string, values: string[], operator = 'eq'): Filter => ({ key: [key], values, operator, mode: 'or' });
const filterGroup = (filters: Filter[], mode: 'and' | 'or' = 'and', filterGroups: FilterGroupInput[] = []): FilterGroupInput => ({ mode, filters, filterGroups });

const filterValues = (value: IrPresetValue): string[] => [
  ...value.entities.map((e) => e.value),
  ...value.terms,
  ...(value.number !== null ? [String(value.number)] : []),
];

// What one rule brings to a requirement: the parts of a criterion, and the same rule as a condition
interface RuleParts {
  criterion: Partial<IrCriterionDraft>;
  condition: Pick<IrConditionDraft, 'filters' | 'link'>;
}

const fromFilters = (fg: unknown, flags: string[]): RuleParts => {
  const filters = JSON.stringify(fg);
  return { criterion: { kind: 'attribute', target_types: flags, target_filters: filters }, condition: { filters, link: null } };
};

const buildParts = (def: IrPresetRule, value: IrPresetValue, flags: string[], groupName: string, groups: IrGroupDraft[]): RuleParts => {
  const addGroup = (patch: Partial<IrGroupDraft>, suffix = ''): string => {
    const group = { ...emptyGroup(), name: `${groupName}${suffix}`, ...patch };
    groups.push(group);
    return group.id;
  };
  const graph = (groupIds: string[], relationships: string[], direction: IrDirection): RuleParts => {
    const link: IrLinkDraft = { relationship_types: relationships, group_ids: groupIds };
    return {
      criterion: { kind: 'graph', from_group_ids: groupIds, relationship_types: relationships, direction, target_types: flags },
      condition: { filters: null, link },
    };
  };
  const typeGroup = (types: string[], suffix = '') => addGroup({
    kind: 'filter',
    role: 'context',
    filters: JSON.stringify(filterGroup([filter('entity_type', types)])),
  }, suffix);
  const { build } = def;
  switch (build.kind) {
    case 'entityFilter':
      return fromFilters(filterGroup([filter(build.key, filterValues(value), build.operator)]), flags);
    case 'motivation':
      return fromFilters(filterGroup([
        filter('primary_motivation', value.terms),
        filter('secondary_motivations', value.terms),
      ], 'or'), flags);
    case 'fixedFilter':
      return fromFilters(build.filters, flags);
    case 'oneOf': {
      const groupId = addGroup({ kind: 'list', role: 'entry', entities: value.entities });
      return {
        criterion: { kind: 'attribute', from_group_ids: [groupId], target_types: flags },
        condition: { filters: JSON.stringify(filterGroup([filter('ids', value.entities.map((e) => e.value))])), link: null },
      };
    }
    case 'linked': {
      const groupIds: string[] = [];
      if (value.entities.length > 0) groupIds.push(addGroup({ kind: 'list', role: 'context', entities: value.entities }));
      if (value.types.length > 0) groupIds.push(typeGroup(value.types, groupIds.length > 0 ? ' (types)' : ''));
      return graph(groupIds, build.relationships, build.direction);
    }
    case 'linkedViaFilter': {
      const groupId = addGroup({
        kind: 'filter',
        role: 'context',
        filters: JSON.stringify(filterGroup([filter('entity_type', [build.anchorType]), filter(build.anchorKey, value.terms)])),
      });
      return graph([groupId], build.relationships, build.direction);
    }
    case 'container':
      return graph([typeGroup(value.types)], ['object'], 'outgoing');
    case 'containerFixed': {
      const groupId = addGroup({ kind: 'filter', role: 'context', filters: JSON.stringify(build.filters) });
      return graph([groupId], ['object'], 'outgoing');
    }
    case 'indicated':
      return graph([typeGroup(['Indicator'])], ['indicates'], 'outgoing');
    case 'domains':
      return fromFilters(filterGroup([], 'or', [
        filterGroup([filter('entity_type', ['Email-Addr']), filter('value', value.terms, 'ends_with')]),
        filterGroup([filter('entity_type', ['User-Account']), filter('account_login', value.terms, 'ends_with')]),
        filterGroup([filter('entity_type', ['Credential']), filter('value', value.terms, 'contains')]),
      ]), flags);
    case 'keywords': {
      const groupId = addGroup({ kind: 'keywords', role: 'entry', keywords: value.terms });
      return { criterion: { kind: 'keywords', from_group_ids: [groupId] }, condition: { filters: null, link: null } };
    }
    default:
      throw new Error('Unknown preset rule build');
  }
};

export const presetItemsToDraft = (
  general: IrPresetGeneral,
  pirType: IrPirType,
  flags: string[],
  items: IrPresetItem[],
): IrDraft => {
  const draft = emptyDraft();
  const groups: IrGroupDraft[] = [];
  const criteria: IrCriterionDraft[] = [];
  const t = (s: string) => s;
  const criterionOf = (name: string, parts: RuleParts): IrCriterionDraft => ({
    ...emptyCriterion([]),
    id: newId('c'),
    ...parts.criterion,
    name,
    mode: 'auto',
    conditions: [],
  });
  items.forEach((item) => {
    if (item.kind === 'custom') {
      criteria.push(criterionOf(item.name, { criterion: { kind: 'attribute', target_types: flags, target_filters: item.filters }, condition: { filters: null, link: null } }));
      return;
    }
    const rules = item.kind === 'rule' ? [item.rule] : item.rules;
    if (rules.length === 0) return;
    const [first, ...others] = rules;
    const criterion = criterionOf(item.name, buildParts(getRule(first.ruleKey), first.value, flags, item.name, groups));
    others.forEach((rule) => {
      const name = defaultRuleName(pirType, rule, t);
      const { condition } = buildParts(getRule(rule.ruleKey), rule.value, flags, name, groups);
      criterion.conditions.push({ ...emptyCondition(), name, applies_to_types: [], ...condition });
    });
    criteria.push(criterion);
  });
  return {
    ...draft,
    name: general.name,
    question: general.question,
    description: general.description,
    priority: general.priority,
    groups,
    criteria,
  };
};
// endregion
