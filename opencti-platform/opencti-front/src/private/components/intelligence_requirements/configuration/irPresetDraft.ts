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
  type IrPriority,
} from './irConfigTypes';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
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

// "any <Type>" is the entitiesOrType choice; container types are plain type names
export const valueLabels = (def: IrPresetRule, value: IrPresetValue, t: Translate): string[] => [
  ...value.entities.map((e) => e.label),
  ...value.types.map((type) => (def.value === 'entitiesOrType' ? `${t('any')} ${t(type)}` : t(type))),
  ...value.terms,
  ...(value.number !== null ? [String(value.number)] : []),
];

const hasValue = (value: IrPresetValue) => value.entities.length + value.types.length + value.terms.length > 0 || value.number !== null;

const namedValues = (def: IrPresetRule, value: IrPresetValue, t: Translate): string => {
  const labels = valueLabels(def, value, t);
  const shown = labels.slice(0, MAX_NAMED_VALUES).join(', ');
  return labels.length > MAX_NAMED_VALUES ? `${shown} +${labels.length - MAX_NAMED_VALUES} more` : shown;
};

const subjectOf = (pirType: IrPirType, t: Translate) => t(IR_PIR_TYPES.find((p) => p.key === pirType)?.subject ?? 'Entities');

export const defaultRuleName = (pirType: IrPirType, rule: IrRuleInstance, t: Translate): string => {
  const def = getRule(rule.ruleKey);
  const subject = subjectOf(pirType, t);
  const verb = t(def.verb);
  if (def.value === 'none') return `${subject} ${verb}`;
  const values = namedValues(def, rule.value, t);
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
export interface IrQueryChip {
  key: string;
  operator?: '=' | '≥'; // '=' when absent
  values: string;
  fromUser: boolean;
}

const FILTER_KEY_LABELS: Record<string, string> = {
  entity_type: 'Entity type',
  response_types: 'Response types',
  x_opencti_cisa_kev: 'CISA KEV',
  objectLabel: 'Label',
  malware_types: 'Malware type',
  sophistication: 'Sophistication',
  resource_level: 'Resource level',
  capabilities: 'Capability',
  x_opencti_cvss_base_score: 'CVSS score',
  x_opencti_epss_score: 'EPSS score',
  account_type: 'Account type',
};

const keyLabel = (key: string) => FILTER_KEY_LABELS[key] ?? key;

// Rules reading as "<flagged> -relationship-> <anchor>": the chips show the relationship and both sides
const relationshipOf = (def: IrPresetRule): { label: string; direction: IrDirection } | null => {
  const { build } = def;
  switch (build.kind) {
    case 'linked':
    case 'linkedViaFilter':
      return { label: build.relationships.join(', '), direction: build.direction };
    case 'container':
    case 'containerFixed':
      return { label: 'object (contained in)', direction: 'outgoing' };
    case 'indicated':
      return { label: 'indicates', direction: 'outgoing' };
    default:
      return null;
  }
};

const valueKeyLabel = (def: IrPresetRule): string => {
  const { build } = def;
  switch (build.kind) {
    case 'entityFilter': return keyLabel(build.key);
    case 'motivation': return 'Motivation';
    case 'keywords': return 'Keyword';
    case 'domains': return 'Domain';
    case 'oneOf': return 'Entity';
    default: return def.sentence;
  }
};

// The constraints a rule fixes itself, as chips (kev, data leak)
const fixedChips = (filters: FilterGroup, t: Translate, skipKeys: string[] = []): IrQueryChip[] => filters.filters
  .filter((f) => !skipKeys.includes(f.key))
  .map((f) => ({ key: t(keyLabel(f.key)), operator: '=', values: f.values.join(', '), fromUser: false }));

export const presetQueryChips = (rule: IrRuleInstance, flags: string[], t: Translate): IrQueryChip[] => {
  const def = getRule(rule.ruleKey);
  const { build } = def;
  const flagged = flags.join(', ');
  const values = valueLabels(def, rule.value, t).join(', ');
  const userChips = (key: string): IrQueryChip[] => (def.value === 'none' ? [] : [{ key: t(key), operator: '=', values, fromUser: true }]);
  const relation = relationshipOf(def);
  if (relation) {
    const flaggedIsSource = relation.direction === 'incoming';
    const fixedSource: IrQueryChip[] = [];
    if (build.kind === 'indicated') fixedSource.push({ key: t('Source type'), operator: '=', values: 'Indicator', fromUser: false });
    if (build.kind === 'containerFixed') {
      const types = build.filters.filters.find((f) => f.key === 'entity_type');
      if (types) fixedSource.push({ key: t('Source type'), operator: '=', values: types.values.join(', '), fromUser: false });
      fixedSource.push(...fixedChips(build.filters, t, ['entity_type']));
    }
    const flaggedChip: IrQueryChip = { key: t(flaggedIsSource ? 'Source type' : 'Target type'), operator: '=', values: flagged, fromUser: false };
    return [
      { key: t('Relationship type'), operator: '=', values: relation.label, fromUser: false },
      // a fixed container query is described by its own constraints
      ...(build.kind === 'containerFixed' ? fixedSource : [...fixedSource, flaggedChip, ...userChips(flaggedIsSource ? 'Target' : 'Source')]),
    ];
  }
  const entityType: IrQueryChip = { key: t('Entity type'), operator: '=', values: flagged, fromUser: false };
  if (build.kind === 'fixedFilter') return [entityType, ...fixedChips(build.filters, t)];
  const operator: IrQueryChip['operator'] = build.kind === 'entityFilter' && build.operator === 'gte' ? '≥' : '=';
  return [entityType, ...userChips(valueKeyLabel(def)).map((chip) => ({ ...chip, operator }))];
};
// endregion

// region conversion to the draft
// Backend format: keys are lists (the catalogue's front-format FilterGroup keeps a string key, so it is not reused here)
type BackendFilter = { key: string[]; values: string[]; operator: string; mode: 'or' };
type BackendFilterGroup = { mode: 'and' | 'or'; filters: BackendFilter[]; filterGroups: BackendFilterGroup[] };

const filter = (key: string, values: string[], operator = 'eq'): BackendFilter => ({ key: [key], values, operator, mode: 'or' });
const filterGroup = (filters: BackendFilter[], mode: 'and' | 'or' = 'and', filterGroups: BackendFilterGroup[] = []): BackendFilterGroup => ({ mode, filters, filterGroups });

const filterValues = (value: IrPresetValue): string[] => [
  ...value.entities.map((e) => e.value),
  ...value.terms,
  ...(value.number !== null ? [String(value.number)] : []),
];

// What one rule brings to a requirement, as a criterion or as a condition of one.
// `groups` are the subject groups it creates: only those the criterion (entry) or the condition (context) references.
interface RuleParts {
  criterion: Partial<IrCriterionDraft>;
  condition: Pick<IrConditionDraft, 'filters' | 'link'>;
  groups: IrGroupDraft[];
}

const fromFilters = (fg: unknown, flags: string[]): RuleParts => {
  const filters = JSON.stringify(fg);
  return { criterion: { kind: 'attribute', target_types: flags, target_filters: filters }, condition: { filters, link: null }, groups: [] };
};

const buildParts = (def: IrPresetRule, value: IrPresetValue, flags: string[], groupName: string, asCriterion: boolean): RuleParts => {
  const groups: IrGroupDraft[] = [];
  // groups of a graph criterion are its entry points; groups of a link condition are context
  const anchorRole = asCriterion ? 'entry' : 'context';
  const addGroup = (patch: Partial<IrGroupDraft>, suffix = ''): string => {
    const group = { ...emptyGroup(), name: `${groupName}${suffix}`, ...patch };
    groups.push(group);
    return group.id;
  };
  const typeGroup = (filters: string, suffix = '') => addGroup({ kind: 'filter', role: anchorRole, filters }, suffix);
  const entityTypeGroup = (types: string[], suffix = '') => typeGroup(JSON.stringify(filterGroup([filter('entity_type', types)])), suffix);
  const graph = (groupIds: string[], relationships: string[], direction: IrDirection): RuleParts => ({
    criterion: { kind: 'graph', from_group_ids: groupIds, relationship_types: relationships, direction, target_types: flags },
    condition: { filters: null, link: { relationship_types: relationships, group_ids: groupIds } },
    groups,
  });
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
      // as a condition, the entities are an ids filter: no subject group
      const condition = { filters: JSON.stringify(filterGroup([filter('ids', value.entities.map((e) => e.value))])), link: null };
      if (!asCriterion) return { criterion: {}, condition, groups };
      const groupId = addGroup({ kind: 'list', role: 'entry', entities: value.entities });
      return { criterion: { kind: 'attribute', from_group_ids: [groupId], target_types: flags }, condition, groups };
    }
    case 'linked': {
      const groupIds: string[] = [];
      if (value.entities.length > 0) groupIds.push(addGroup({ kind: 'list', role: anchorRole, entities: value.entities }));
      if (value.types.length > 0) groupIds.push(entityTypeGroup(value.types, groupIds.length > 0 ? ' (types)' : ''));
      return graph(groupIds, build.relationships, build.direction);
    }
    case 'linkedViaFilter':
      return graph([typeGroup(JSON.stringify(filterGroup([filter('entity_type', [build.anchorType]), filter(build.anchorKey, value.terms)])))], build.relationships, build.direction);
    case 'container':
      return graph([entityTypeGroup(value.types)], ['object'], 'outgoing');
    case 'containerFixed':
      return graph([typeGroup(JSON.stringify(build.filters))], ['object'], 'outgoing');
    case 'indicated':
      return graph([entityTypeGroup(['Indicator'])], ['indicates'], 'outgoing');
    case 'domains':
      return fromFilters(filterGroup([], 'or', [
        filterGroup([filter('entity_type', ['Email-Addr']), filter('value', value.terms, 'ends_with')]),
        filterGroup([filter('entity_type', ['User-Account']), filter('account_login', value.terms, 'ends_with')]),
        filterGroup([filter('entity_type', ['Credential']), filter('value', value.terms, 'contains')]),
      ]), flags);
    case 'keywords': {
      if (!asCriterion) throw new Error('A keywords rule cannot be a condition of a group');
      const groupId = addGroup({ kind: 'keywords', role: 'entry', keywords: value.terms });
      return { criterion: { kind: 'keywords', from_group_ids: [groupId], target_types: flags }, condition: { filters: null, link: null }, groups };
    }
    default: {
      const unhandled: never = build;
      throw new Error(`Unknown preset rule build: ${JSON.stringify(unhandled)}`);
    }
  }
};

// A container rule cannot be a condition: the engine reads an `object` link from the flagged entity as
// "it contains a member", the reverse of "it is mentioned in". In a group, it is the rule that makes the criterion.
export const isContainerRule = (ruleKey: string) => ['container', 'containerFixed'].includes(getRule(ruleKey).build.kind);
const containerFirst = (rules: IrRuleInstance[]): IrRuleInstance[] => [
  ...rules.filter((rule) => isContainerRule(rule.ruleKey)),
  ...rules.filter((rule) => !isContainerRule(rule.ruleKey)),
];

export const presetItemsToDraft = (
  general: IrPresetGeneral,
  pirType: IrPirType,
  flags: string[],
  items: IrPresetItem[],
): IrDraft => {
  const groups: IrGroupDraft[] = [];
  const criteria: IrCriterionDraft[] = [];
  const t = (s: string) => s;
  const criterionOf = (name: string, parts: Pick<RuleParts, 'criterion'>): IrCriterionDraft => ({
    ...emptyCriterion([]),
    id: newId('c'),
    ...parts.criterion,
    name,
    mode: 'auto',
    conditions: [],
  });
  items.forEach((item) => {
    if (item.kind === 'custom') {
      criteria.push(criterionOf(item.name, { criterion: { kind: 'attribute', target_types: flags, target_filters: item.filters } }));
      return;
    }
    const rules = item.kind === 'rule' ? [item.rule] : containerFirst(item.rules);
    if (rules.length === 0) return;
    const [first, ...others] = rules;
    const firstParts = buildParts(getRule(first.ruleKey), first.value, flags, item.name, true);
    groups.push(...firstParts.groups);
    const criterion = criterionOf(item.name, firstParts);
    others.forEach((rule) => {
      const name = defaultRuleName(pirType, rule, t);
      const parts = buildParts(getRule(rule.ruleKey), rule.value, flags, name, false);
      groups.push(...parts.groups);
      criterion.conditions.push({ ...emptyCondition(), name, applies_to_types: [], ...parts.condition });
    });
    criteria.push(criterion);
  });
  return {
    ...emptyDraft(),
    name: general.name,
    question: general.question,
    description: general.description,
    priority: general.priority,
    groups,
    criteria,
  };
};
// endregion
