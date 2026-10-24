// Proof of concept of a generic PIR model (feature flag INTELLIGENCE_REQUIREMENTS).
// Local draft of the configuration in four blocks, converted to the GraphQL input on save.

export type IrPriority = 'critical' | 'high' | 'medium' | 'low';
export type IrStatus = 'active' | 'paused';
export type IrGroupKind = 'list' | 'filter' | 'keywords';
export type IrGroupRole = 'entry' | 'context' | 'both';
export type IrCriterionKind = 'graph' | 'attribute' | 'keywords';
export type IrCriterionMode = 'auto' | 'propose' | 'off';
export type IrDirection = 'outgoing' | 'incoming' | 'both';

export interface IrEntityOption {
  value: string; // internal id
  label: string;
  type: string;
}

// A condition of the simplified filter builder: one OpenCTI filter
export interface IrCondition {
  key: string;
  operator: string;
  value: string;
}

export interface IrKiqDraft {
  id: string;
  text: string;
  criteria_ids: string[];
}

export interface IrGroupDraft {
  id: string;
  name: string;
  kind: IrGroupKind;
  role: IrGroupRole;
  entities: IrEntityOption[];
  conditions: IrCondition[];
  keywords: string[];
}

export interface IrCriterionDraft {
  id: string;
  name: string;
  kind: IrCriterionKind;
  from_group_ids: string[];
  from_in_requirement: boolean;
  relationship_types: string[];
  direction: IrDirection;
  target_types: string[];
  target_conditions: IrCondition[];
  keyword_fields: string[];
  mode: IrCriterionMode;
}

export interface IrPathConditionDraft {
  relationship_types: string[];
  direction: IrDirection;
  target_relationship_type: string;
  targets: IrEntityOption[];
}

export interface IrRuleDraft {
  id: string;
  name: string;
  applies_to_types: string[];
  applies_to_criterion_id: string | null;
  conditions: IrCondition[];
  path_condition: IrPathConditionDraft | null;
  points: number;
  required: boolean;
  enabled: boolean;
}

export interface IrDraft {
  name: string;
  description: string;
  question: string;
  priority: IrPriority;
  status: IrStatus;
  thresholds: string; // "50, 80"
  rescan_days: number;
  kiqs: IrKiqDraft[];
  groups: IrGroupDraft[];
  criteria: IrCriterionDraft[];
  rules: IrRuleDraft[];
}

export const newId = (prefix: string) => `${prefix}-${Math.random().toString(36).slice(2, 8)}`;

export const emptyDraft = (): IrDraft => ({
  name: '',
  description: '',
  question: '',
  priority: 'medium',
  status: 'active',
  thresholds: '50, 80',
  rescan_days: 30,
  kiqs: [],
  groups: [{ id: newId('g'), name: 'Subjects', kind: 'list', role: 'entry', entities: [], conditions: [], keywords: [] }],
  criteria: [],
  rules: [],
});

export const emptyGroup = (): IrGroupDraft => ({ id: newId('g'), name: '', kind: 'list', role: 'entry', entities: [], conditions: [], keywords: [] });

export const emptyCriterion = (groups: IrGroupDraft[]): IrCriterionDraft => ({
  id: newId('c'),
  name: '',
  kind: 'graph',
  from_group_ids: groups.filter((g) => g.role !== 'context').slice(0, 1).map((g) => g.id),
  from_in_requirement: false,
  relationship_types: [],
  direction: 'outgoing',
  target_types: [],
  target_conditions: [],
  keyword_fields: ['name', 'description', 'content'],
  mode: 'auto',
});

export const emptyRule = (): IrRuleDraft => ({
  id: newId('r'),
  name: '',
  applies_to_types: [],
  applies_to_criterion_id: null,
  conditions: [],
  path_condition: null,
  points: 10,
  required: false,
  enabled: true,
});

export const emptyPathCondition = (): IrPathConditionDraft => ({ relationship_types: [], direction: 'incoming', target_relationship_type: 'targets', targets: [] });

// region filters <-> conditions
interface FilterGroupLike {
  mode: string;
  filters: { key: string[] | string; values: string[]; operator?: string | null; mode?: string | null }[];
  filterGroups: unknown[];
}

export const conditionsToFilters = (conditions: IrCondition[]): FilterGroupLike | null => {
  const valid = conditions.filter((c) => c.key && c.value !== '');
  if (valid.length === 0) return null;
  return {
    mode: 'and',
    filters: valid.map((c) => ({ key: [c.key], values: [c.value], operator: c.operator, mode: 'or' })),
    filterGroups: [],
  };
};

export const filtersToConditions = (filters: string | null | undefined): IrCondition[] => {
  if (!filters) return [];
  try {
    const parsed = JSON.parse(filters) as FilterGroupLike;
    return (parsed.filters ?? []).map((f) => ({
      key: Array.isArray(f.key) ? f.key[0] : f.key,
      operator: f.operator ?? 'eq',
      value: f.values?.[0] ?? '',
    }));
  } catch {
    return [];
  }
};
// endregion

export const parseThresholds = (value: string) => value
  .split(',')
  .map((v) => Number.parseInt(v.trim(), 10))
  .filter((v) => !Number.isNaN(v));

/**
 * Build the GraphQL input (IntelligenceRequirementInput) from the draft.
 */
export const draftToInput = (draft: IrDraft) => ({
  name: draft.name,
  description: draft.description || null,
  ir_question: draft.question,
  ir_priority: draft.priority,
  ir_status: draft.status,
  ir_thresholds: parseThresholds(draft.thresholds),
  ir_rescan_days: draft.rescan_days,
  ir_kiqs: draft.kiqs.filter((k) => k.text.trim()).map((k) => ({ id: k.id, text: k.text, criteria_ids: k.criteria_ids })),
  ir_subject_groups: draft.groups.map((g) => ({
    id: g.id,
    name: g.name || g.id,
    kind: g.kind,
    role: g.role,
    entity_ids: g.kind === 'list' ? g.entities.map((e) => e.value) : [],
    filters: g.kind === 'filter' ? conditionsToFilters(g.conditions) : null,
    keywords: g.kind === 'keywords' ? g.keywords : [],
  })),
  ir_scope_criteria: draft.criteria.map((c) => ({
    id: c.id,
    name: c.name || c.id,
    kind: c.kind,
    from_group_ids: c.kind === 'attribute' ? [] : c.from_group_ids,
    from_in_requirement: c.kind === 'graph' ? c.from_in_requirement : false,
    relationship_types: c.kind === 'graph' ? c.relationship_types : [],
    direction: c.direction,
    target_types: c.target_types,
    target_filters: conditionsToFilters(c.target_conditions),
    keyword_fields: c.keyword_fields,
    mode: c.mode,
  })),
  ir_relevance_rules: draft.rules.map((r) => ({
    id: r.id,
    name: r.name || r.id,
    applies_to_types: r.applies_to_types,
    applies_to_criterion_id: r.applies_to_criterion_id,
    filters: conditionsToFilters(r.conditions),
    path_condition: r.path_condition && r.path_condition.relationship_types.length > 0 ? {
      relationship_types: r.path_condition.relationship_types,
      direction: r.path_condition.direction,
      target_relationship_type: r.path_condition.target_relationship_type,
      target_ids: r.path_condition.targets.map((t) => t.value),
    } : null,
    points: r.points,
    required: r.required,
    enabled: r.enabled,
  })),
});
