import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { IntelligenceRequirementInput } from '../../generated/graphql';
import { fullRelationsList, internalFindByIds, internalLoadById } from '../../database/middleware-loader';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { normalizeIntelligenceRequirementInput, parseIrFilters } from './intelligenceRequirement-config';
import type { ParsedIntelligenceRequirement, StoreIrCriterion } from './intelligenceRequirement-types';
import type { BasicStoreEntityIntelligenceRequirementMatch, StoreIrMatchExplanation } from './intelligenceRequirementMatch-types';
import {
  buildEngineState,
  evaluateCandidate,
  findKeyword,
  IR_CONTAINS_RELATIONSHIP,
  type IrCandidate,
  type IrEngineState,
  isEntityMatchingFilters,
  isTypeMatching,
} from './intelligenceRequirement-engine';
import { computeMatchEligibility, computeMatchScore, isCandidateEligible } from './intelligenceRequirement-scoring';
import { entityDisplayName } from './intelligenceRequirementItem-domain';

// Dry run of a configuration on one entity (configuration screen): would it enter the requirement, through which criterion,
// does it meet the conditions of the scope, which rules give points. The configuration does not need to be saved: nothing is written.

const SECOND_HOP_ANCHORS_MAX = 20;
const CONTAINERS_MAX = 50;
const DRY_RUN_ID = 'dry-run';

const isEntryCriterion = (c: StoreIrCriterion) => c.mode !== 'off' && (c.kind === 'attribute' || c.kind === 'graph');

const pseudoMatch = (entity: { id: string; type: string }, criteriaIds: string[]) => ({
  match_entity_id: entity.id,
  match_entity_type: entity.type,
  match_criteria_ids: criteriaIds,
  match_status: 'auto',
}) as unknown as BasicStoreEntityIntelligenceRequirementMatch;

/**
 * Second hop criteria start from the entities of the requirement. For a configuration being written, they are not stored yet:
 * the entities linked to the tested one by these criteria are evaluated against the first hop criteria (one level), and those
 * that would be part of the requirement count as starting points. For a saved requirement, its stored entities count too.
 */
const secondHopAnchors = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, state: IrEngineState, entity: { id: string; type: string }) => {
  const anchors = new Set<string>(state.inRequirement);
  const firstHop = ir.ir_scope_criteria.filter((c) => isEntryCriterion(c) && !c.from_in_requirement);
  const secondHop = ir.ir_scope_criteria.filter((c) => isEntryCriterion(c) && c.kind === 'graph' && c.from_in_requirement && isTypeMatching(entity.type, c.target_types));
  for (let i = 0; i < secondHop.length; i += 1) {
    const criterion = secondHop[i];
    const sides: { outgoing: boolean; args: { fromId?: string; toId?: string } }[] = [];
    if (criterion.direction === 'outgoing' || criterion.direction === 'both') sides.push({ outgoing: true, args: { toId: entity.id } });
    if (criterion.direction === 'incoming' || criterion.direction === 'both') sides.push({ outgoing: false, args: { fromId: entity.id } });
    for (let j = 0; j < sides.length; j += 1) {
      const relations = (await fullRelationsList<BasicStoreRelation>(context, user, criterion.relationship_types, sides[j].args)).slice(0, SECOND_HOP_ANCHORS_MAX);
      for (let k = 0; k < relations.length; k += 1) {
        const anchor = sides[j].outgoing ? { id: relations[k].fromId, type: relations[k].fromType } : { id: relations[k].toId, type: relations[k].toType };
        if (anchors.has(anchor.id) || ((criterion.from_types ?? []).length > 0 && !isTypeMatching(anchor.type, criterion.from_types ?? []))) continue;
        const candidates = await evaluateCandidate(context, user, state, anchor, firstHop);
        for (let c = 0; c < candidates.length; c += 1) {
          if (await isCandidateEligible(context, user, ir, anchor, candidates[c].criterion.id)) {
            anchors.add(anchor.id);
            break;
          }
        }
      }
    }
  }
  return anchors;
};

/**
 * Keyword criteria: the keyword in the texts of the entity itself, or in the texts of a container (report, note...) that contains it
 * (that is how its contained objects enter). The texts are read as they are stored today.
 */
const keywordCandidates = async (context: AuthContext, user: AuthUser, state: IrEngineState, stored: BasicStoreEntity, criteria: StoreIrCriterion[]) => {
  const entity = { id: stored.internal_id, type: stored.entity_type };
  const candidates: IrCandidate[] = [];
  let containers: BasicStoreEntity[] | null = null;
  const at = new Date().toISOString();
  for (let i = 0; i < criteria.length; i += 1) {
    const criterion = criteria[i];
    if (!await isEntityMatchingFilters(context, user, entity.id, parseIrFilters(criterion.target_filters))) continue;
    const keywords = criterion.from_group_ids.flatMap((gid) => state.keywords.get(gid) ?? []);
    const excluded = criterion.from_group_ids.flatMap((gid) => state.excludedKeywords.get(gid) ?? []);
    if (keywords.length === 0) continue;
    const own = findKeyword(stored, keywords, criterion.keyword_fields, excluded);
    if (own) {
      candidates.push({ entity, criterion, explanation: { criterion_id: criterion.id, kind: 'keywords', at, keyword: own.keyword, field: own.field } });
    } else {
      if (containers === null) {
        const relations = (await fullRelationsList<BasicStoreRelation>(context, user, [IR_CONTAINS_RELATIONSHIP], { toId: entity.id })).slice(0, CONTAINERS_MAX);
        containers = await internalFindByIds<BasicStoreEntity>(context, user, relations.map((r) => r.fromId)) as BasicStoreEntity[];
      }
      for (let j = 0; j < containers.length; j += 1) {
        const hit = findKeyword(containers[j], keywords, criterion.keyword_fields, excluded);
        if (hit) {
          candidates.push({
            entity,
            criterion,
            explanation: { criterion_id: criterion.id, kind: 'keywords', at, keyword: hit.keyword, field: hit.field, container_id: containers[j].internal_id, container_type: containers[j].entity_type },
          });
          break;
        }
      }
    }
  }
  return candidates;
};

const proofText = async (context: AuthContext, user: AuthUser, explanation: StoreIrMatchExplanation) => {
  if (explanation.kind === 'graph' && explanation.anchor_id) {
    const anchor = await entityDisplayName(context, user, explanation.anchor_id);
    return explanation.direction === 'outgoing'
      ? `${anchor} —${explanation.relationship_type}→ this entity`
      : `this entity —${explanation.relationship_type}→ ${anchor}`;
  }
  if (explanation.kind === 'keywords') {
    if (explanation.container_id) {
      const container = await entityDisplayName(context, user, explanation.container_id);
      return `Contained in “${container}”, whose ${explanation.field} mentions “${explanation.keyword}”`;
    }
    return `Its ${explanation.field} mentions “${explanation.keyword}”`;
  }
  return 'Member of the starting points';
};

export const testIntelligenceRequirementEntity = async (
  context: AuthContext,
  user: AuthUser,
  input: IntelligenceRequirementInput,
  entityId: string,
  irId?: string | null,
) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const config = normalizeIntelligenceRequirementInput(input);
  const ir = {
    id: irId ?? DRY_RUN_ID,
    ir_kiqs: config.kiqs,
    ir_subject_groups: config.groups,
    ir_scope_criteria: config.criteria,
    ir_relevance_rules: config.rules,
    ir_thresholds: input.ir_thresholds ?? [],
  } as unknown as ParsedIntelligenceRequirement;
  const stored = await internalLoadById<BasicStoreEntity>(context, user, entityId);
  if (!stored) throw FunctionalError('Entity not found', { entityId });
  const entity = { id: stored.internal_id, type: stored.entity_type };
  const notes: string[] = [];
  const engineState = await buildEngineState(context, user, ir);
  const state: IrEngineState = { ...engineState, inRequirement: await secondHopAnchors(context, user, ir, engineState, entity) };
  // The criteria that could bring an entity of this type, and those that actually do
  const reachable = ir.ir_scope_criteria.filter((c) => c.mode !== 'off' && isTypeMatching(entity.type, c.target_types));
  const keywordCriteria = reachable.filter((c) => c.kind === 'keywords');
  const candidates = [
    ...await evaluateCandidate(context, user, state, entity, reachable.filter(isEntryCriterion)),
    ...await keywordCandidates(context, user, state, stored, keywordCriteria),
  ];
  if (keywordCriteria.length > 0) notes.push('Keywords are searched in the texts as they are stored today, in the entity and in up to 50 containers that contain it.');
  const criteria = [];
  const eligibleIds: string[] = [];
  let firstUnmet: string | null = null;
  for (let i = 0; i < reachable.length; i += 1) {
    const criterion = reachable[i];
    const candidate = candidates.find((c) => c.criterion.id === criterion.id);
    let conditions: { name: string; met: boolean }[] = [];
    if (candidate) {
      const { outcomes } = await computeMatchEligibility(context, user, ir, pseudoMatch(entity, [criterion.id]));
      conditions = outcomes.map((o) => ({ name: o.name, met: o.hit }));
      if (conditions.every((c) => c.met)) eligibleIds.push(criterion.id);
      else firstUnmet = firstUnmet ?? conditions.find((c) => !c.met)?.name ?? null;
    }
    criteria.push({
      criterion_id: criterion.id,
      name: criterion.name,
      kind: criterion.kind,
      matched: !!candidate,
      proof: candidate ? await proofText(context, user, candidate.explanation) : null,
      conditions,
    });
  }
  const eligible = eligibleIds.length > 0;
  const result = eligible ? await computeMatchScore(context, user, ir, pseudoMatch(entity, eligibleIds)) : null;
  const rules = (result?.breakdown ?? [])
    .filter((o) => o.kind === 'rule' && o.reason !== 'not applicable')
    .map((o) => ({ name: o.name, points: o.points, hit: o.hit, reason: o.reason || null }));
  const proposedOnly = eligible && eligibleIds.every((id) => ir.ir_scope_criteria.find((c) => c.id === id)?.mode === 'propose');
  let verdict: string;
  if (reachable.length === 0) verdict = `Not in the requirement: no criterion brings a ${entity.type}`;
  else if (candidates.length === 0) verdict = 'Not in the requirement: no criterion brings it today';
  else if (!eligible) verdict = `Not in the requirement: “${firstUnmet ?? 'a condition of the scope'}” is not met`;
  else if (proposedOnly) verdict = `Proposed for review, score ${result?.score ?? 0}`;
  else verdict = `In the requirement, score ${result?.score ?? 0}`;
  return {
    entity_id: entity.id,
    entity_name: extractEntityRepresentativeName(stored),
    entity_type: entity.type,
    in_requirement: eligible,
    score: result?.score ?? 0,
    verdict,
    criteria,
    rules,
    notes,
  };
};
