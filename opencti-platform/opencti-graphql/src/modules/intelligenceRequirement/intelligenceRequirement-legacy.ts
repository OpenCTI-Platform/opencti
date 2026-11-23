import { type FilterGroup, FilterMode, FilterOperator, PirType } from '../../generated/graphql';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import type { StoreIrCriterion, StoreIrRule, StoreIrSubjectGroup } from './intelligenceRequirement-types';
import { IR_DEFAULT_THRESHOLDS } from './intelligenceRequirement-config';

// Bridge between the legacy PIR model (Pir entity, weighted relationship criteria, in-pir flags)
// and the intelligence requirement engine. The Pir stays the public contract (GraphQL API, in-pir stream events,
// "Listen PIR events" playbook entry, pir_information on the flagged entity); its requirement drives it.
//
// A legacy criterion is a filter group on a relationship event: an entity_type filter (the relationship types)
// and a toId filter (the targets), the source of the relationship being flagged. It becomes:
// - a list subject group holding the targets (the anchors),
// - a graph criterion read in the incoming direction: (anchor) <-relationship- (entity that enters),
// - a scoring rule giving the weight of the criterion, as a share of 100.
// The legacy pir_filters and any other filter of a criterion apply to the relationship event, not to the entity:
// they are kept on the criterion as relationship_filters.

export interface LegacyPirCriterionInput {
  weight: number;
  filters: FilterGroup;
}

export interface LegacyPirInput {
  name: string;
  description?: string | null;
  pir_type: PirType | string;
  pir_rescan_days: number;
  pir_filters: FilterGroup;
  pir_criteria: LegacyPirCriterionInput[];
}

export interface LegacyRequirementConfiguration {
  name: string;
  description: string;
  ir_question: string;
  ir_priority: string;
  ir_status: string;
  ir_subject_groups: StoreIrSubjectGroup[];
  ir_scope_criteria: StoreIrCriterion[];
  ir_relevance_rules: StoreIrRule[];
  ir_thresholds: number[];
  ir_rescan_days: number;
  ir_brief_frequency: string;
}

// The source types a threat landscape PIR flags (constructFinalPirFilters of the legacy engine)
export const LEGACY_THREAT_LANDSCAPE_TYPES = [ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_MALWARE];

const RELATIONSHIP_TYPE_KEY = 'entity_type';
const TARGET_KEY = 'toId';
const SOURCE_TYPES_KEY = 'fromTypes';

export const legacyCriterionId = (index: number) => `pir-criterion-${index}`;
export const legacyGroupId = (index: number) => `pir-targets-${index}`;
export const legacyRuleId = (index: number) => `pir-weight-${index}`;

const firstKey = (key: string | string[]) => (Array.isArray(key) ? key[0] : key);

const isEmptyGroup = (group: FilterGroup) => group.filters.length === 0 && group.filterGroups.length === 0;

/**
 * Split a legacy criterion filter group into its relationship types, its targets, the source types it names
 * and what is left (kept as relationship filters). Only the top level filters of an AND group are read as structure:
 * an OR group or nested groups are kept whole as relationship filters.
 */
export const splitLegacyCriterionFilters = (filters: FilterGroup) => {
  const relationshipTypes: string[] = [];
  const targetIds: string[] = [];
  const sourceTypes: string[] = [];
  if (filters.mode !== FilterMode.And && filters.filters.length > 1) {
    return { relationshipTypes, targetIds, sourceTypes, rest: filters };
  }
  const restFilters = filters.filters.filter((f) => {
    const key = firstKey(f.key);
    const isEq = !f.operator || f.operator === FilterOperator.Eq;
    if (key === RELATIONSHIP_TYPE_KEY && isEq) {
      relationshipTypes.push(...f.values.map(String));
      return false;
    }
    if (key === TARGET_KEY && isEq) {
      targetIds.push(...f.values.map(String));
      return false;
    }
    if (key === SOURCE_TYPES_KEY && isEq) {
      sourceTypes.push(...f.values.map(String));
      return false;
    }
    return true;
  });
  const rest: FilterGroup = { ...filters, filters: restFilters };
  return { relationshipTypes, targetIds, sourceTypes, rest: isEmptyGroup(rest) ? null : rest };
};

const mergeRelationshipFilters = (a: FilterGroup | null, b: FilterGroup | null): FilterGroup | null => {
  if (!a) return b;
  if (!b) return a;
  return { mode: FilterMode.And, filters: [], filterGroups: [a, b] };
};

/**
 * Points of each legacy criterion as a share of 100, for the requirement screens.
 * The score written back to the Pir is computed by legacyPirScore, which rounds the sum (not each share) like the legacy engine.
 */
export const legacyWeightPoints = (weights: number[]) => {
  const total = weights.reduce((acc, w) => acc + w, 0);
  if (total <= 0) return weights.map(() => 0);
  return weights.map((w) => Math.round((w / total) * 100));
};

/**
 * The legacy PIR score of an entity: the weights of the criteria it matches (each counted once) over the sum of every weight.
 * Same formula as computePirScore of the legacy engine.
 */
export const legacyPirScore = (weights: number[], matchedCriterionIds: string[]) => {
  const total = weights.reduce((acc, w) => acc + w, 0);
  if (total <= 0) return 0;
  const matched = new Set(matchedCriterionIds);
  const hit = weights.reduce((acc, w, index) => (matched.has(legacyCriterionId(index)) ? acc + w : acc), 0);
  return Math.round((hit / total) * 100);
};

/**
 * Configuration of the requirement that drives a legacy PIR. Pure: no read, deterministic ids,
 * so a migration run twice builds the same configuration.
 */
export const legacyPirToRequirement = (pir: LegacyPirInput): LegacyRequirementConfiguration => {
  const isLandscape = pir.pir_type === PirType.ThreatLandscape;
  const pirFilters = pir.pir_filters && !isEmptyGroup(pir.pir_filters) ? pir.pir_filters : null;
  const weights = pir.pir_criteria.map((c) => c.weight);
  const points = legacyWeightPoints(weights);
  const groups: StoreIrSubjectGroup[] = [];
  const criteria: StoreIrCriterion[] = [];
  const rules: StoreIrRule[] = [];
  pir.pir_criteria.forEach((legacy, index) => {
    const { relationshipTypes, targetIds, sourceTypes, rest } = splitLegacyCriterionFilters(legacy.filters);
    const criterionName = `Criterion ${index + 1}`;
    groups.push({
      id: legacyGroupId(index),
      name: `${criterionName} targets`,
      kind: 'list',
      role: 'entry',
      entity_ids: targetIds,
      filters: null,
      keywords: [],
    });
    const relationshipFilters = mergeRelationshipFilters(pirFilters, rest);
    criteria.push({
      id: legacyCriterionId(index),
      name: criterionName,
      kind: 'graph',
      from_group_ids: [legacyGroupId(index)],
      from_in_requirement: false,
      relationship_types: relationshipTypes,
      direction: 'incoming',
      target_types: sourceTypes.length > 0 ? sourceTypes : (isLandscape ? LEGACY_THREAT_LANDSCAPE_TYPES : []),
      target_filters: null,
      relationship_filters: relationshipFilters ? JSON.stringify(relationshipFilters) : null,
      keyword_fields: [],
      mode: 'auto',
      conditions: [],
    });
    rules.push({
      id: legacyRuleId(index),
      name: `${criterionName} (weight ${legacy.weight})`,
      applies_to_types: [],
      applies_to_criterion_id: legacyCriterionId(index),
      filters: null,
      link: null,
      path_condition: null,
      points: points[index],
      required: false,
      enabled: true,
    });
  });
  return {
    name: pir.name,
    description: pir.description ?? '',
    ir_question: pir.description || pir.name,
    ir_priority: 'medium',
    ir_status: 'active',
    ir_subject_groups: groups,
    ir_scope_criteria: criteria,
    ir_relevance_rules: rules,
    ir_thresholds: IR_DEFAULT_THRESHOLDS,
    ir_rescan_days: pir.pir_rescan_days,
    ir_brief_frequency: 'off',
  };
};
