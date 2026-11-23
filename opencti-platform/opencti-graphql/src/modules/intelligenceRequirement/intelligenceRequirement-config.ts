import { FunctionalError } from '../../config/errors';
import type { FilterGroup, IntelligenceRequirementInput } from '../../generated/graphql';
import { getParentTypes } from '../../schema/schemaUtils';
import type {
  BasicStoreEntityIntelligenceRequirement,
  StoreIrCondition,
  StoreIrCriterion,
  StoreIrKiq,
  StoreIrRule,
  StoreIrSubjectGroup,
  ParsedIntelligenceRequirement,
} from './intelligenceRequirement-types';
import { IR_KEYWORD_FIELDS } from './intelligenceRequirement-types';

export const IR_DEFAULT_THRESHOLDS = [50, 80];
export const IR_DEFAULT_RESCAN_DAYS = 30;

const parseJsonArray = <T>(value: string | null | undefined): T[] => {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const serializeFilters = (filters: FilterGroup | null | undefined) => (filters ? JSON.stringify(filters) : null);

type LinkInput = { relationship_types?: string[] | null; group_ids?: string[] | null } | null | undefined;
type PathInput = { relationship_types: string[]; direction: string; target_relationship_type: string; target_ids: string[]; target_group_ids?: string[] | null } | null | undefined;
const normalizeLink = (link: LinkInput) => (link && (link.group_ids ?? []).length > 0
  ? { relationship_types: link.relationship_types ?? [], group_ids: link.group_ids ?? [] }
  : null);
const normalizePath = (path: PathInput) => (path ? { ...path, target_group_ids: path.target_group_ids ?? [] } : null);

export const parseIrFilters = (filters: string | null | undefined): FilterGroup | null => {
  if (!filters) return null;
  try {
    return JSON.parse(filters) as FilterGroup;
  } catch {
    return null;
  }
};

const parentTypes = (type: string): string[] => {
  try {
    return getParentTypes(type);
  } catch {
    return []; // abstract type
  }
};

// Two lists of entity types share a type (directly or through a parent type); an empty list means any type
export const typesOverlap = (a: string[], b: string[]) => a.length === 0 || b.length === 0 || a.some((x) => b.some((y) => (
  x === y || parentTypes(x).includes(y) || parentTypes(y).includes(x)
)));

/**
 * Legacy "required" relevance rules become scope conditions of the criteria that bring the types they apply to
 * (or of their criterion), so that what may enter the requirement is expressed in its scope only.
 * Their points, if any, are kept as a plain scoring rule. Idempotent.
 */
export const convertRequiredRules = (criteria: StoreIrCriterion[], rules: StoreIrRule[]) => {
  const required = rules.filter((r) => r.required);
  if (required.length === 0) return { criteria, rules };
  const placed = new Set<string>();
  const converted = criteria.map((c) => {
    const conditions = [...(c.conditions ?? [])];
    required.filter((r) => r.enabled).forEach((r) => {
      const applies = r.applies_to_criterion_id ? r.applies_to_criterion_id === c.id : typesOverlap(c.target_types, r.applies_to_types);
      if (applies) placed.add(r.id);
      if (applies && !conditions.some((cond) => cond.id === r.id)) {
        conditions.push({
          id: r.id,
          name: r.name.replace(/\s*\(required\)\s*$/i, ''),
          applies_to_types: r.applies_to_types,
          filters: r.filters,
          link: r.link ?? null,
          path_condition: r.path_condition,
        });
      }
    });
    return { ...c, conditions };
  });
  // A rule placed nowhere (unknown criterion, no criterion bringing its types) is kept, so that validation reports it
  const scoring = rules
    .filter((r) => !r.required || r.points !== 0 || !placed.has(r.id))
    .map((r) => (r.required ? { ...r, name: r.name.replace(/\s*\(required\)\s*$/i, ''), required: false } : r));
  return { criteria: converted, rules: scoring };
};

/**
 * Parse the serialized configuration blocks of a stored requirement.
 */
export const parseIntelligenceRequirement = (ir: BasicStoreEntityIntelligenceRequirement): ParsedIntelligenceRequirement => {
  const { criteria, rules } = convertRequiredRules(
    parseJsonArray<StoreIrCriterion>(ir.ir_scope_criteria).map((c) => ({ ...c, conditions: c.conditions ?? [] })),
    parseJsonArray<StoreIrRule>(ir.ir_relevance_rules),
  );
  return {
    ...ir,
    ir_kiqs: parseJsonArray<StoreIrKiq>(ir.ir_kiqs),
    ir_subject_groups: parseJsonArray<StoreIrSubjectGroup>(ir.ir_subject_groups),
    ir_scope_criteria: criteria,
    ir_relevance_rules: rules,
  };
};

/**
 * Normalize the GraphQL input into the configuration blocks (defaults filled, filters serialized).
 */
export const normalizeIntelligenceRequirementInput = (input: IntelligenceRequirementInput) => {
  const kiqs: StoreIrKiq[] = (input.ir_kiqs ?? []).map((k) => ({ id: k.id, text: k.text, criteria_ids: k.criteria_ids ?? [] }));
  const groups: StoreIrSubjectGroup[] = input.ir_subject_groups.map((g) => ({
    id: g.id,
    name: g.name,
    kind: g.kind,
    role: g.role,
    entity_ids: g.entity_ids ?? [],
    filters: serializeFilters(g.filters),
    keywords: (g.keywords ?? []).map((k) => k.trim()).filter((k) => k.length > 0),
    exclude_keywords: (g.exclude_keywords ?? []).map((k) => k.trim()).filter((k) => k.length > 0),
  }));
  const inputCriteria: StoreIrCriterion[] = input.ir_scope_criteria.map((c) => ({
    id: c.id,
    name: c.name ?? c.id,
    kind: c.kind,
    from_group_ids: c.from_group_ids ?? [],
    from_in_requirement: c.from_in_requirement ?? false,
    from_types: c.from_types ?? [],
    relationship_types: c.relationship_types ?? [],
    direction: c.direction ?? 'both',
    target_types: c.target_types ?? [],
    target_filters: serializeFilters(c.target_filters),
    keyword_fields: c.keyword_fields && c.keyword_fields.length > 0 ? c.keyword_fields : IR_KEYWORD_FIELDS,
    mode: c.mode,
    conditions: (c.conditions ?? []).map((cond): StoreIrCondition => ({
      id: cond.id,
      name: cond.name,
      applies_to_types: cond.applies_to_types ?? [],
      filters: serializeFilters(cond.filters),
      link: normalizeLink(cond.link),
      path_condition: normalizePath(cond.path_condition),
    })),
  }));
  const inputRules: StoreIrRule[] = (input.ir_relevance_rules ?? []).map((r) => ({
    id: r.id,
    name: r.name,
    applies_to_types: r.applies_to_types ?? [],
    applies_to_criterion_id: r.applies_to_criterion_id ?? null,
    filters: serializeFilters(r.filters),
    link: normalizeLink(r.link),
    path_condition: normalizePath(r.path_condition),
    points: r.points,
    required: r.required ?? false,
    enabled: r.enabled ?? true,
  }));
  const { criteria: scopedCriteria, rules } = convertRequiredRules(inputCriteria, inputRules);
  return { kiqs, groups, criteria: scopedCriteria, rules };
};

const assertUniqueIds = (block: string, ids: string[]) => {
  const seen = new Set<string>();
  ids.forEach((id) => {
    if (seen.has(id)) throw FunctionalError(`Duplicate id in ${block}`, { id });
    seen.add(id);
  });
};

/**
 * Check the consistency between the four blocks (references, required fields per kind).
 */
export const validateIntelligenceRequirementConfig = (config: ReturnType<typeof normalizeIntelligenceRequirementInput>) => {
  const { kiqs, groups, criteria, rules } = config;
  assertUniqueIds('subjects', groups.map((g) => g.id));
  assertUniqueIds('scope', criteria.map((c) => c.id));
  assertUniqueIds('relevance', rules.map((r) => r.id));
  assertUniqueIds('kiqs', kiqs.map((k) => k.id));
  const groupIds = new Set(groups.map((g) => g.id));
  const criterionIds = new Set(criteria.map((c) => c.id));
  // Links and path targets reference groups that have members (a keywords group has none)
  const entityGroupIds = new Set(groups.filter((g) => g.kind !== 'keywords').map((g) => g.id));
  const checkReferences = (item: StoreIrCondition | StoreIrRule, where: Record<string, string>) => {
    if (item.link) {
      if (item.link.relationship_types.length === 0) throw FunctionalError('A link to a subject group needs at least one relationship type', where);
      item.link.group_ids.forEach((gid) => {
        if (!entityGroupIds.has(gid)) throw FunctionalError('A link references an unknown or keywords subject group', { ...where, group: gid });
      });
    }
    if (item.path_condition) {
      const path = item.path_condition;
      if (path.relationship_types.length === 0 || path.target_ids.length + (path.target_group_ids ?? []).length === 0) {
        throw FunctionalError('A path condition needs relationship types and targets', where);
      }
      (path.target_group_ids ?? []).forEach((gid) => {
        if (!entityGroupIds.has(gid)) throw FunctionalError('A path condition references an unknown or keywords subject group', { ...where, group: gid });
      });
    }
  };
  groups.forEach((g) => {
    if (g.kind === 'list' && g.entity_ids.length === 0) throw FunctionalError('A list subject group needs at least one entity', { group: g.id });
    if (g.kind === 'filter' && !g.filters) throw FunctionalError('A filter subject group needs filters', { group: g.id });
    if (g.kind === 'keywords' && g.keywords.length === 0) throw FunctionalError('A keywords subject group needs at least one keyword', { group: g.id });
  });
  criteria.forEach((c) => {
    c.from_group_ids.forEach((gid) => {
      if (!groupIds.has(gid)) throw FunctionalError('Scope criterion references an unknown subject group', { criterion: c.id, group: gid });
    });
    if (c.kind === 'graph') {
      if (c.from_group_ids.length === 0 && !c.from_in_requirement) throw FunctionalError('A graph criterion needs a starting subject group', { criterion: c.id });
      if (c.relationship_types.length === 0) throw FunctionalError('A graph criterion needs at least one relationship type', { criterion: c.id });
    }
    if (c.kind === 'attribute' && c.target_types.length === 0 && !c.target_filters && c.from_group_ids.length === 0) {
      throw FunctionalError('An attribute criterion needs target types, filters or subject groups', { criterion: c.id });
    }
    if (c.kind === 'attribute') {
      c.from_group_ids.forEach((gid) => {
        if (!entityGroupIds.has(gid)) throw FunctionalError('An attribute criterion can only bring the members of a list or filter subject group', { criterion: c.id, group: gid });
      });
    }
    (c.conditions ?? []).forEach((cond) => {
      if (!cond.filters && !cond.path_condition && !cond.link) {
        throw FunctionalError('A scope condition needs filters, a link to a subject group or a path condition', { criterion: c.id, condition: cond.id });
      }
      checkReferences(cond, { criterion: c.id, condition: cond.id });
    });
    assertUniqueIds(`conditions of ${c.id}`, (c.conditions ?? []).map((cond) => cond.id));
    if (c.kind === 'keywords') {
      const keywordGroups = groups.filter((g) => c.from_group_ids.includes(g.id) && g.kind === 'keywords');
      if (keywordGroups.length === 0) throw FunctionalError('A keywords criterion needs a keywords subject group', { criterion: c.id });
    }
  });
  rules.forEach((r) => {
    checkReferences(r, { rule: r.id });
    if (r.applies_to_criterion_id && !criterionIds.has(r.applies_to_criterion_id)) {
      throw FunctionalError('Relevance rule references an unknown scope criterion', { rule: r.id, criterion: r.applies_to_criterion_id });
    }
  });
  kiqs.forEach((k) => {
    k.criteria_ids.forEach((cid) => {
      if (!criterionIds.has(cid)) throw FunctionalError('KIQ references an unknown scope criterion', { kiq: k.id, criterion: cid });
    });
  });
};

/**
 * Build the stored attributes from the GraphQL input.
 */
export const serializeIntelligenceRequirementInput = (input: IntelligenceRequirementInput) => {
  const config = normalizeIntelligenceRequirementInput(input);
  validateIntelligenceRequirementConfig(config);
  return {
    name: input.name,
    description: input.description ?? '',
    ir_question: input.ir_question,
    ir_priority: input.ir_priority,
    ir_status: input.ir_status ?? 'active',
    ir_kiqs: JSON.stringify(config.kiqs),
    ir_subject_groups: JSON.stringify(config.groups),
    ir_scope_criteria: JSON.stringify(config.criteria),
    ir_relevance_rules: JSON.stringify(config.rules),
    ir_thresholds: input.ir_thresholds && input.ir_thresholds.length > 0 ? input.ir_thresholds : IR_DEFAULT_THRESHOLDS,
    ir_rescan_days: input.ir_rescan_days ?? IR_DEFAULT_RESCAN_DAYS,
    ir_brief_frequency: input.ir_brief_frequency ?? 'off',
  };
};
