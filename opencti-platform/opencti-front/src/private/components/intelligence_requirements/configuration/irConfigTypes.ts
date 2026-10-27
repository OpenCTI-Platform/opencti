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
  filters: string | null; // OpenCTI filter group, backend format
  keywords: string[];
  exclude_keywords: string[];
}

export interface IrCriterionDraft {
  id: string;
  name: string;
  kind: IrCriterionKind;
  from_group_ids: string[];
  from_in_requirement: boolean;
  from_types: string[];
  relationship_types: string[];
  direction: IrDirection;
  target_types: string[];
  target_filters: string | null;
  keyword_fields: string[];
  mode: IrCriterionMode;
  conditions: IrConditionDraft[]; // all must be met (AND) for an entity to enter through this criterion
}

export interface IrPathConditionDraft {
  relationship_types: string[];
  direction: IrDirection;
  target_relationship_type: string;
  targets: IrEntityOption[];
  target_group_ids: string[]; // the members of these subject groups are targets too
}

// Linked by one of the relationship types to a member of one of the subject groups (object: contains one)
export interface IrLinkDraft {
  relationship_types: string[];
  group_ids: string[];
}

// A condition of a criterion (scope): what an entity brought by the criterion must also satisfy to enter
export interface IrConditionDraft {
  id: string;
  name: string;
  applies_to_types: string[]; // empty = every type the criterion brings
  filters: string | null;
  link: IrLinkDraft | null;
  path_condition: IrPathConditionDraft | null;
}

// A scoring rule (relevance): only ranks the entities of the requirement
export interface IrRuleDraft {
  id: string;
  name: string;
  applies_to_types: string[];
  applies_to_criterion_id: string | null;
  filters: string | null;
  link: IrLinkDraft | null;
  path_condition: IrPathConditionDraft | null;
  points: number;
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
  brief_frequency: 'off' | 'daily' | 'weekly';
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
  brief_frequency: 'off',
  kiqs: [],
  groups: [{ id: newId('g'), name: 'Subjects', kind: 'list', role: 'entry', entities: [], filters: null, keywords: [], exclude_keywords: [] }],
  criteria: [],
  rules: [],
});

export const emptyGroup = (): IrGroupDraft => ({ id: newId('g'), name: '', kind: 'list', role: 'entry', entities: [], filters: null, keywords: [], exclude_keywords: [] });

export const emptyCriterion = (groups: IrGroupDraft[]): IrCriterionDraft => ({
  id: newId('c'),
  name: '',
  kind: 'graph',
  from_group_ids: groups.filter((g) => g.role !== 'context').slice(0, 1).map((g) => g.id),
  from_in_requirement: false,
  from_types: [],
  relationship_types: [],
  direction: 'outgoing',
  target_types: [],
  target_filters: null,
  keyword_fields: ['name', 'description', 'content'],
  mode: 'auto',
  conditions: [],
});

export const emptyCondition = (): IrConditionDraft => ({ id: newId('k'), name: '', applies_to_types: [], filters: null, link: null, path_condition: null });

export const emptyLink = (): IrLinkDraft => ({ relationship_types: ['targets'], group_ids: [] });

export const emptyRule = (): IrRuleDraft => ({
  id: newId('r'),
  name: '',
  applies_to_types: [],
  applies_to_criterion_id: null,
  filters: null,
  link: null,
  path_condition: null,
  points: 10,
  enabled: true,
});

export const emptyPathCondition = (): IrPathConditionDraft => ({ relationship_types: [], direction: 'incoming', target_relationship_type: 'targets', targets: [], target_group_ids: [] });

const parseFilters = (filters: string | null) => {
  if (!filters) return null;
  try {
    return JSON.parse(filters);
  } catch {
    return null;
  }
};

const pathConditionToInput = (path: IrPathConditionDraft | null) => (path && path.relationship_types.length > 0 ? {
  relationship_types: path.relationship_types,
  direction: path.direction,
  target_relationship_type: path.target_relationship_type,
  target_ids: path.targets.map((t) => t.value),
  target_group_ids: path.target_group_ids,
} : null);

const linkToInput = (link: IrLinkDraft | null) => (link && link.group_ids.length > 0 && link.relationship_types.length > 0 ? link : null);

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
  ir_brief_frequency: draft.brief_frequency,
  ir_kiqs: draft.kiqs.filter((k) => k.text.trim()).map((k) => ({ id: k.id, text: k.text, criteria_ids: k.criteria_ids })),
  ir_subject_groups: draft.groups.map((g) => ({
    id: g.id,
    name: g.name || g.id,
    kind: g.kind,
    role: g.role,
    entity_ids: g.kind === 'list' ? g.entities.map((e) => e.value) : [],
    filters: g.kind === 'filter' ? parseFilters(g.filters) : null,
    keywords: g.kind === 'keywords' ? g.keywords : [],
    exclude_keywords: g.kind === 'keywords' ? g.exclude_keywords : [],
  })),
  ir_scope_criteria: draft.criteria.map((c) => ({
    id: c.id,
    name: c.name || c.id,
    kind: c.kind,
    from_group_ids: c.from_group_ids,
    from_in_requirement: c.kind === 'graph' ? c.from_in_requirement : false,
    from_types: c.kind === 'graph' ? c.from_types : [],
    relationship_types: c.kind === 'graph' ? c.relationship_types : [],
    direction: c.direction,
    target_types: c.target_types,
    target_filters: parseFilters(c.target_filters),
    keyword_fields: c.keyword_fields,
    mode: c.mode,
    conditions: c.conditions.map((k) => ({
      id: k.id,
      name: k.name || k.id,
      applies_to_types: k.applies_to_types,
      filters: parseFilters(k.filters),
      link: linkToInput(k.link),
      path_condition: pathConditionToInput(k.path_condition),
    })),
  })),
  ir_relevance_rules: draft.rules.map((r) => ({
    id: r.id,
    name: r.name || r.id,
    applies_to_types: r.applies_to_types,
    applies_to_criterion_id: r.applies_to_criterion_id,
    filters: parseFilters(r.filters),
    link: linkToInput(r.link),
    path_condition: pathConditionToInput(r.path_condition),
    points: r.points,
    enabled: r.enabled,
  })),
});

// region proposal of the AI assisted creation (an IntelligenceRequirementInput as JSON) -> draft of the form
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonInput = Record<string, any>;

const filtersToString = (filters: unknown): string | null => {
  if (!filters) return null;
  return typeof filters === 'string' ? filters : JSON.stringify(filters);
};

const str = (value: unknown, fallback = '') => (typeof value === 'string' ? value : fallback);
const list = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v) => typeof v === 'string') : []);

const directionOf = (value: unknown, fallback: IrDirection): IrDirection => (['outgoing', 'incoming', 'both'].includes(value as string) ? value as IrDirection : fallback);

// Legacy proposals may still carry "required" rules: they are shown as conditions of the criteria bringing their types
const overlaps = (a: string[], b: string[]) => a.length === 0 || b.length === 0 || a.some((x) => b.some((y) => x === y || x.startsWith(`${y}-`) || y.startsWith(`${x}-`)));

export const inputToDraft = (input: JsonInput, entities: Map<string, IrEntityOption>): IrDraft => {
  const option = (id: string): IrEntityOption => entities.get(id) ?? { value: id, label: id, type: '' };
  const pathOf = (path: JsonInput | null | undefined): IrPathConditionDraft | null => (path && list(path.relationship_types).length > 0 ? {
    relationship_types: list(path.relationship_types),
    direction: directionOf(path.direction, 'incoming'),
    target_relationship_type: str(path.target_relationship_type, 'targets'),
    targets: list(path.target_ids).map(option),
    target_group_ids: list(path.target_group_ids),
  } : null);
  const linkOf = (link: JsonInput | null | undefined): IrLinkDraft | null => (link && list(link.group_ids).length > 0
    ? { relationship_types: list(link.relationship_types), group_ids: list(link.group_ids) }
    : null);
  const conditionOf = (k: JsonInput): IrConditionDraft => ({
    id: str(k.id, newId('k')),
    name: str(k.name).replace(/\s*\(required\)\s*$/i, ''),
    applies_to_types: list(k.applies_to_types),
    filters: filtersToString(k.filters),
    link: linkOf(k.link),
    path_condition: pathOf(k.path_condition),
  });
  const rules: JsonInput[] = input.ir_relevance_rules ?? [];
  const required = rules.filter((r) => r.required === true && r.enabled !== false);
  return {
    name: str(input.name),
    description: str(input.description),
    question: str(input.ir_question),
    priority: (['critical', 'high', 'medium', 'low'].includes(input.ir_priority) ? input.ir_priority : 'medium') as IrPriority,
    status: input.ir_status === 'active' ? 'active' : 'paused',
    thresholds: (Array.isArray(input.ir_thresholds) && input.ir_thresholds.length > 0 ? input.ir_thresholds : [50, 80]).join(', '),
    rescan_days: Number.isInteger(input.ir_rescan_days) ? input.ir_rescan_days : 30,
    brief_frequency: (['daily', 'weekly'].includes(input.ir_brief_frequency) ? input.ir_brief_frequency : 'off') as IrDraft['brief_frequency'],
    kiqs: (input.ir_kiqs ?? []).map((k: JsonInput) => ({ id: str(k.id, newId('k')), text: str(k.text), criteria_ids: list(k.criteria_ids) })),
    groups: (input.ir_subject_groups ?? []).map((g: JsonInput) => ({
      id: str(g.id, newId('g')),
      name: str(g.name),
      kind: (['list', 'filter', 'keywords'].includes(g.kind) ? g.kind : 'list') as IrGroupKind,
      role: (['entry', 'context', 'both'].includes(g.role) ? g.role : 'entry') as IrGroupRole,
      entities: list(g.entity_ids).map(option),
      filters: filtersToString(g.filters),
      keywords: list(g.keywords),
      exclude_keywords: list(g.exclude_keywords),
    })),
    criteria: (input.ir_scope_criteria ?? []).map((c: JsonInput) => ({
      id: str(c.id, newId('c')),
      name: str(c.name),
      kind: (['graph', 'attribute', 'keywords'].includes(c.kind) ? c.kind : 'graph') as IrCriterionKind,
      from_group_ids: list(c.from_group_ids),
      from_in_requirement: c.from_in_requirement === true,
      from_types: list(c.from_types),
      relationship_types: list(c.relationship_types),
      direction: directionOf(c.direction, 'outgoing'),
      target_types: list(c.target_types),
      target_filters: filtersToString(c.target_filters),
      keyword_fields: list(c.keyword_fields).length > 0 ? list(c.keyword_fields) : ['name', 'description', 'content'],
      mode: (['auto', 'propose', 'off'].includes(c.mode) ? c.mode : 'auto') as IrCriterionMode,
      conditions: [
        ...(Array.isArray(c.conditions) ? c.conditions : []).map(conditionOf),
        ...required
          .filter((r) => (typeof r.applies_to_criterion_id === 'string' ? r.applies_to_criterion_id === c.id : overlaps(list(c.target_types), list(r.applies_to_types))))
          .filter((r) => !(Array.isArray(c.conditions) ? c.conditions : []).some((k: JsonInput) => k.id === r.id))
          .map(conditionOf),
      ],
    })),
    rules: rules.filter((r) => r.required !== true || (Number.isFinite(r.points) && r.points !== 0)).map((r: JsonInput) => ({
      id: str(r.id, newId('r')),
      name: str(r.name).replace(/\s*\(required\)\s*$/i, ''),
      applies_to_types: list(r.applies_to_types),
      applies_to_criterion_id: typeof r.applies_to_criterion_id === 'string' ? r.applies_to_criterion_id : null,
      filters: filtersToString(r.filters),
      link: linkOf(r.link),
      path_condition: pathOf(r.path_condition),
      points: Number.isFinite(r.points) ? r.points : 10,
      enabled: r.enabled !== false,
    })),
  };
};
// endregion
