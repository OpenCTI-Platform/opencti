import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { fullRelationsList, internalFindByIds, pageRelationsConnection } from '../../database/middleware-loader';
import { READ_RELATIONSHIPS_INDICES } from '../../database/utils';
import { elBulk, ES_RETRY_ON_CONFLICT } from '../../database/engine';
import { patchAttribute } from '../../database/middleware';
import { type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import type { ParsedIntelligenceRequirement, StoreIrCondition, StoreIrGroupLink, StoreIrPathCondition, StoreIrRule } from './intelligenceRequirement-types';
import { type BasicStoreEntityIntelligenceRequirementMatch, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, type StoreIrMatchHistoryPoint } from './intelligenceRequirementMatch-types';
import { parseIrFilters } from './intelligenceRequirement-config';
import { IR_CONTAINS_RELATIONSHIP, isEntityMatchingFilters, isTypeMatching } from './intelligenceRequirement-engine';
import { groupMemberIds } from './intelligenceRequirement-groups';

// Eligibility (scope): an entity is part of the requirement when at least one of the criteria that brought it
// has all its conditions met for it (conditions that apply to its type). A candidate that does not meet them is not stored;
// it is evaluated again when a fact that a condition reads arrives on it. A stored entity that no longer meets them leaves,
// unless an analyst accepted it: it then stays as not eligible (hidden, not a starting point of the second hop).
// Relevance: score = sum of the points of the matching rules, capped 0-100. Rules only rank, they never exclude.

export interface IrRuleOutcome {
  rule_id: string;
  name: string;
  points: number;
  hit: boolean;
  reason: string; // '' | 'not applicable' | 'condition not met' | 'scope condition not met'
  kind: 'rule' | 'condition';
  criterion_id?: string; // kind = condition
}

export interface IrScoreResult {
  score: number;
  excluded: boolean;
  breakdown: IrRuleOutcome[];
}

const resolveInternalIds = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const entities = await internalFindByIds<BasicStoreEntity>(context, user, ids) as BasicStoreEntity[];
  return Array.from(new Set([...ids, ...entities.map((e) => e.internal_id)]));
};

/**
 * Path condition: the entity is linked by one of relationship_types to an entity
 * that has a target_relationship_type relationship toward one of target_ids.
 * Example: Vulnerability ←exploits— (threat) —targets→ Europe
 */
export const isPathConditionMet = async (context: AuthContext, user: AuthUser, entityId: string, condition: StoreIrPathCondition, groupTargetIds: string[] = []) => {
  const linked = new Set<string>();
  if (condition.direction === 'incoming' || condition.direction === 'both') {
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, condition.relationship_types, { toId: entityId });
    relations.forEach((r) => linked.add(r.fromId));
  }
  if (condition.direction === 'outgoing' || condition.direction === 'both') {
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, condition.relationship_types, { fromId: entityId });
    relations.forEach((r) => linked.add(r.toId));
  }
  if (linked.size === 0 || condition.target_ids.length + groupTargetIds.length === 0) return false;
  const targetIds = [...await resolveInternalIds(context, user, condition.target_ids), ...groupTargetIds];
  const targeting = await fullRelationsList<BasicStoreRelation>(context, user, [condition.target_relationship_type], {
    fromId: Array.from(linked),
    toId: targetIds,
  });
  return targeting.length > 0;
};

const isRuleApplicable = (rule: StoreIrRule, match: BasicStoreEntityIntelligenceRequirementMatch) => {
  if (!isTypeMatching(match.match_entity_type, rule.applies_to_types ?? [])) return false;
  return !rule.applies_to_criterion_id || (match.match_criteria_ids ?? []).includes(rule.applies_to_criterion_id);
};

/**
 * Link to subject groups: the entity has one of the relationship types with a member of the groups (either direction),
 * or contains one ("object", for a container).
 * Relationships: the few relationships of the entity are read (inferred ones included) and compared with the members kept
 * in memory, instead of searching the relationships of thousands of members (a group of every malware or every software).
 * Containers: the content of the entity is matched by the search engine (inferred content included).
 */
const isLinkMet = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, entityId: string, link: StoreIrGroupLink) => {
  const relationshipTypes = link.relationship_types.filter((r) => r !== IR_CONTAINS_RELATIONSHIP);
  if (relationshipTypes.length > 0) {
    const members = await groupMemberIds(context, user, ir, link.group_ids);
    if (members.length > 0) {
      // Existence only: one relationship between the entity and a member, in either direction, stops the search
      const sides = [{ fromId: entityId, toId: members }, { fromId: members, toId: entityId }];
      for (let i = 0; i < sides.length; i += 1) {
        const page = await pageRelationsConnection<BasicStoreRelation>(context, user, relationshipTypes, { ...sides[i], first: 1, indices: READ_RELATIONSHIPS_INDICES });
        if (page.edges.length > 0) return true;
      }
    }
  }
  if (link.relationship_types.includes(IR_CONTAINS_RELATIONSHIP)) {
    const members = await groupMemberIds(context, user, ir, link.group_ids);
    if (members.length === 0) return false;
    const filters: FilterGroup = { mode: FilterMode.Or, filters: [{ key: ['objects'], values: members, operator: FilterOperator.Eq, mode: FilterMode.Or }], filterGroups: [] };
    return isEntityMatchingFilters(context, user, entityId, filters);
  }
  return false;
};

// Filters, link to subject groups and path condition of a rule or a condition, evaluated on the entity (all must hold)
const isConditionMet = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, entityId: string, condition: StoreIrCondition | StoreIrRule) => {
  if (!await isEntityMatchingFilters(context, user, entityId, parseIrFilters(condition.filters))) return false;
  if (condition.link && condition.link.group_ids.length > 0 && !await isLinkMet(context, user, ir, entityId, condition.link)) return false;
  if (condition.path_condition) {
    const groupTargets = await groupMemberIds(context, user, ir, condition.path_condition.target_group_ids ?? []);
    return isPathConditionMet(context, user, entityId, condition.path_condition, groupTargets);
  }
  return true;
};

/**
 * Eligibility of a match: one of its criteria has all its applicable conditions met.
 * A match whose criteria are all gone from the configuration stays eligible (no condition left to check).
 */
export const computeMatchEligibility = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
) => {
  const criteria = ir.ir_scope_criteria.filter((c) => (match.match_criteria_ids ?? []).includes(c.id));
  const outcomes: IrRuleOutcome[] = [];
  let eligible = criteria.length === 0;
  for (let i = 0; i < criteria.length; i += 1) {
    const criterion = criteria[i];
    const conditions = (criterion.conditions ?? []).filter((cond) => isTypeMatching(match.match_entity_type, cond.applies_to_types ?? []));
    let all = true;
    for (let j = 0; j < conditions.length; j += 1) {
      const condition = conditions[j];
      const met = await isConditionMet(context, user, ir, match.match_entity_id, condition);
      outcomes.push({ rule_id: condition.id, name: condition.name, points: 0, hit: met, reason: met ? '' : 'scope condition not met', kind: 'condition', criterion_id: criterion.id });
      if (!met) all = false;
    }
    if (all) eligible = true;
  }
  return { eligible, outcomes };
};

/**
 * A candidate brought by a criterion is stored only if it meets the conditions of that criterion
 * (or if it is already stored for another criterion). A criterion without condition for its type admits it at once.
 */
export const isCandidateEligible = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  entity: { id: string; type: string },
  criterionId: string,
) => {
  const criterion = ir.ir_scope_criteria.find((c) => c.id === criterionId);
  const conditions = (criterion?.conditions ?? []).filter((cond) => isTypeMatching(entity.type, cond.applies_to_types ?? []));
  for (let i = 0; i < conditions.length; i += 1) {
    if (!await isConditionMet(context, user, ir, entity.id, conditions[i])) return false;
  }
  return true;
};

export const computeMatchScore = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
): Promise<IrScoreResult> => {
  const { eligible, outcomes } = await computeMatchEligibility(context, user, ir, match);
  const breakdown: IrRuleOutcome[] = [...outcomes];
  let total = 0;
  const rules = ir.ir_relevance_rules.filter((r) => r.enabled);
  for (let i = 0; i < rules.length; i += 1) {
    const rule = rules[i];
    const outcome: IrRuleOutcome = { rule_id: rule.id, name: rule.name, points: 0, hit: false, reason: '', kind: 'rule' };
    if (!isRuleApplicable(rule, match)) {
      outcome.reason = 'not applicable';
    } else if (await isConditionMet(context, user, ir, match.match_entity_id, rule)) {
      outcome.hit = true;
      outcome.points = rule.points;
      total += rule.points;
    } else {
      outcome.reason = 'condition not met';
    }
    breakdown.push(outcome);
  }
  return { score: eligible ? Math.max(0, Math.min(100, total)) : 0, excluded: !eligible, breakdown };
};

export interface IrRescoreResult {
  match: BasicStoreEntityIntelligenceRequirementMatch;
  previousScore: number;
  result: IrScoreResult;
}

// Context of a re-evaluation, kept in the history of the entity
export interface IrChangeMeta {
  at?: string; // date of the stream event that caused it (default: now)
  kind?: StoreIrMatchHistoryPoint['kind'];
  trigger?: string;
}

const MAX_HISTORY = 100;

/**
 * Score and history writes of a batch, sent in one bulk request at its end instead of one update per entity.
 * A match read again during the batch gets the fields still pending (overlay), so that nothing written earlier is lost.
 */
export const createMatchWriter = () => {
  const pending = new Map<string, { index: string; doc: Record<string, unknown> }>();
  return {
    write: (match: BasicStoreEntityIntelligenceRequirementMatch, doc: Record<string, unknown>) => {
      pending.set(match.id, { index: match._index, doc: { ...(pending.get(match.id)?.doc ?? {}), ...doc } });
    },
    overlay: (match: BasicStoreEntityIntelligenceRequirementMatch) => {
      const entry = pending.get(match.id);
      if (entry) Object.assign(match, entry.doc);
    },
    discard: (matchId: string) => {
      pending.delete(matchId);
    },
    flush: async (context: AuthContext) => {
      if (pending.size === 0) return 0;
      const updatedAt = new Date().toISOString();
      const body = Array.from(pending.entries()).flatMap(([id, { index, doc }]) => [
        { update: { _index: index, _id: id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
        { doc: { ...doc, updated_at: updatedAt } },
      ]);
      const written = pending.size;
      pending.clear();
      await elBulk(context, { refresh: true, body });
      return written;
    },
  };
};
export type IrMatchWriter = ReturnType<typeof createMatchWriter>;

const parseOutcomes = (value: string | undefined | null): IrRuleOutcome[] => {
  try {
    const parsed = JSON.parse(value || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

export const parseMatchHistory = (match: { match_history?: string | null }): StoreIrMatchHistoryPoint[] => {
  try {
    const parsed = JSON.parse(match.match_history || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

/**
 * What a re-evaluation changed: the rules that now give (or no longer give) their points,
 * the conditions of the scope that are now met (or no longer met). For a first evaluation, what holds.
 */
export const diffOutcomes = (previous: IrRuleOutcome[], next: IrRuleOutcome[]) => {
  const key = (o: IrRuleOutcome) => `${o.kind}|${o.criterion_id ?? ''}|${o.rule_id}`;
  const before = new Map(previous.map((o) => [key(o), o]));
  const first = previous.length === 0;
  const changes: string[] = [];
  next.forEach((o) => {
    const prev = before.get(key(o));
    const wasHit = prev?.hit ?? false;
    if (o.kind === 'condition') {
      if (first ? !o.hit : wasHit !== o.hit) changes.push(`${o.name}: ${o.hit ? 'met' : 'not met'}`);
    } else if (o.reason !== 'not applicable' && (first ? o.hit && o.points !== 0 : wasHit !== o.hit)) {
      const points = o.hit ? o.points : (prev?.points ?? 0);
      if (points !== 0) changes.push(`${o.name} ${o.hit === (points > 0) ? '+' : '-'}${Math.abs(points)}`);
    }
  });
  return changes;
};

/**
 * Recompute and store the score of a match, and record the change in its history when its score,
 * its eligibility or its status changed. Returns the previous score to detect threshold crossings.
 */
export const rescoreMatch = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
  meta: IrChangeMeta = {},
  writer?: IrMatchWriter, // engine batch: the write is grouped with the others of the batch
): Promise<IrRescoreResult> => {
  writer?.overlay(match);
  const previousScore = match.match_excluded ? 0 : (match.match_score ?? 0);
  const result = await computeMatchScore(context, user, ir, match);
  const breakdown = JSON.stringify(result.breakdown);
  const history = parseMatchHistory(match);
  const last = history.length > 0 ? history[history.length - 1] : null;
  const eligible = !result.excluded;
  const record = !last || last.score !== result.score || last.eligible !== eligible || last.status !== match.match_status;
  if (record) {
    history.push({
      at: meta.at ?? new Date().toISOString(),
      score: result.score,
      eligible,
      status: match.match_status,
      // The first point of a history says what holds at that moment, the next ones what changed
      kind: last ? (meta.kind ?? 'fact') : 'entry',
      trigger: meta.trigger,
      changes: diffOutcomes(last ? parseOutcomes(match.match_score_breakdown) : [], result.breakdown),
    });
    history.sort((a, b) => a.at.localeCompare(b.at));
  }
  const serializedHistory = record ? JSON.stringify(history.slice(-MAX_HISTORY)) : match.match_history;
  if (record || result.score !== match.match_score || result.excluded !== (match.match_excluded ?? false) || breakdown !== match.match_score_breakdown) {
    const doc = {
      match_score: result.score,
      match_excluded: result.excluded,
      match_score_breakdown: breakdown,
      ...(record ? { match_history: serializedHistory } : {}),
    };
    // A match just created may not carry its index yet: written at once
    if (writer && match._index) writer.write(match, doc);
    else await patchAttribute(context, user, match.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, doc);
  }
  // Keep the in-memory match up to date: the engine reuses it for the next events of the batch
  Object.assign(match, { match_score_breakdown: breakdown, match_history: serializedHistory });
  return { match, previousScore, result };
};

/**
 * Record a decision that does not re-evaluate the entity (rejected, removed): its status changes, its score does not.
 */
export const appendMatchHistory = async (
  context: AuthContext,
  user: AuthUser,
  match: BasicStoreEntityIntelligenceRequirementMatch,
  point: Omit<StoreIrMatchHistoryPoint, 'at' | 'score' | 'eligible' | 'changes'> & { at?: string },
) => {
  const history = parseMatchHistory(match);
  history.push({ ...point, at: point.at ?? new Date().toISOString(), score: match.match_score ?? 0, eligible: !match.match_excluded, changes: [] });
  await patchAttribute(context, user, match.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, { match_history: JSON.stringify(history.slice(-MAX_HISTORY)) });
};

export const topReasons = (result: IrScoreResult) => result.breakdown
  .filter((o) => o.hit && o.points !== 0)
  .sort((a, b) => Math.abs(b.points) - Math.abs(a.points))
  .slice(0, 3)
  .map((o) => `${o.name} ${o.points > 0 ? '+' : ''}${o.points}`);
