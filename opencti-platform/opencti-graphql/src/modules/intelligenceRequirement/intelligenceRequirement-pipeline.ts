import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, type ParsedIntelligenceRequirement } from './intelligenceRequirement-types';
import { type BasicStoreEntityIntelligenceRequirementMatch, IR_MATCH_IN_STATUSES } from './intelligenceRequirementMatch-types';
import { type BasicStoreEntityIntelligenceRequirementItem, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from './intelligenceRequirementItem-types';
import {
  deleteMatch,
  invalidateInRequirementEntityIds,
  listMatches,
  loadMatch,
  loadMatchById,
  updateMatchStatus,
  upsertMatch,
  type UpsertMatchResult,
} from './intelligenceRequirementMatch-domain';
import { buildEngineState, evaluateExistingRelationships, type IrCandidate, type IrEngineState } from './intelligenceRequirement-engine';
import { SYSTEM_USER } from '../../utils/access';
import { appendMatchHistory, type IrChangeMeta, type IrMatchWriter, isCandidateEligible, rescoreMatch, topReasons } from './intelligenceRequirement-scoring';
import { closeItem, closeOpenItemsOfMatch, createItem, entityDisplayName } from './intelligenceRequirementItem-domain';
import { parseIntelligenceRequirement } from './intelligenceRequirement-config';

// Glue between the scope engine, the relevance engine and the inbox:
// every change on an entity of the requirement goes through processMatchChange.

interface MatchChange {
  created?: boolean;
  previousStatus?: string | null; // status before the change (defaults to the current one)
  criterionId?: string;
  displayName?: string;
  quiet?: boolean; // grouped entry (backfill): no per-entity "entered" / "score" item, one summary item instead
  meta?: IrChangeMeta; // date and trigger recorded in the history of the entity
  writer?: IrMatchWriter; // engine batch: score and history writes grouped
}

const isIn = (status: string) => IR_MATCH_IN_STATUSES.includes(status);
// Statuses of an entity that leaves the requirement when it no longer meets the conditions of the scope.
// An accepted entity stays (the analyst decided), as not eligible; rejected and removed ones are kept to remember the decision.
const LEAVES_WHEN_NOT_ELIGIBLE = ['auto', 'proposed'];
export const NOT_ELIGIBLE_RESULT = 'No longer meets the conditions of the scope';

/**
 * A candidate of a criterion: stored (or given a new proof) only if it meets the conditions of the scope of that criterion,
 * or if it is already stored. onSkipped counts the candidates evaluated and not stored.
 */
export const upsertCandidate = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  candidate: IrCandidate,
  onSkipped?: () => void,
) => {
  return upsertMatch(context, user, ir.id, candidate.entity, candidate.criterion, candidate.explanation, async () => {
    const eligible = await isCandidateEligible(context, user, ir, candidate.entity, candidate.criterion.id);
    if (!eligible) onSkipped?.();
    return eligible;
  });
};

/**
 * Re-evaluate an entity of the requirement (eligibility, then score), then create the inbox items implied by the change:
 * - proposed: an entity proposed by a criterion in Propose mode, once it meets the conditions of the scope
 * - entered: an entity that becomes part of the requirement automatically (or now meets the conditions of the scope)
 * - score: a threshold crossed upward (from 0 when the entity just became part of the requirement)
 * Entities that do not meet the conditions of the scope produce no item; automatic and proposed ones leave the requirement
 * (dropped: their match is deleted and their open items closed).
 * becameVisible tells the caller the entity just became part of the requirement (second hop backfill to run).
 */
export const processMatchChange = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
  change: MatchChange = {},
) => {
  const status = match.match_status;
  const previousStatus = change.previousStatus ?? status;
  const wasExcluded = !change.created && (match.match_excluded ?? false);
  const wasVisible = !change.created && isIn(previousStatus) && !wasExcluded;
  const rescore = await rescoreMatch(context, user, ir, match, change.meta, change.writer);
  const { excluded, score } = rescore.result;
  // Keep the in-memory match up to date: the engine reuses it for the next events of the batch
  Object.assign(match, { match_score: score, match_excluded: excluded });
  if (excluded && LEAVES_WHEN_NOT_ELIGIBLE.includes(status)) {
    change.writer?.discard(match.id);
    await closeOpenItemsOfMatch(context, user, ir.id, match.id, NOT_ELIGIBLE_RESULT);
    await deleteMatch(context, user, match.id);
    return { ...rescore, becameVisible: false, dropped: true };
  }
  const visible = isIn(status) && !excluded;
  const itemBase = { entityId: match.match_entity_id, entityType: match.match_entity_type, matchId: match.id };
  let name = change.displayName;
  const getName = async () => {
    if (!name) name = await entityDisplayName(context, user, match.match_entity_id);
    return name;
  };
  // A proposal that is no longer a proposal closes its open "proposed" items
  if (previousStatus === 'proposed' && status !== 'proposed') {
    await closeOpenItemsOfMatch(context, user, ir.id, match.id, status === 'auto' ? 'Entered automatically' : 'Accepted into the requirement', 'proposed');
  }
  if ((change.created || wasExcluded) && status === 'proposed' && !excluded) {
    await createItem(context, user, ir.id, 'proposed', `${await getName()} proposed`, { ...itemBase, data: { criterion_id: change.criterionId } });
  }
  if (visible && !wasVisible && status === 'auto' && !change.quiet) {
    const title = !change.created && isIn(previousStatus) ? `${await getName()} now meets the conditions of the scope` : `${await getName()} entered the requirement`;
    await createItem(context, user, ir.id, 'entered', title, { ...itemBase, data: { criterion_id: change.criterionId } });
  }
  if (visible && !change.quiet) {
    const fromScore = wasVisible ? rescore.previousScore : 0;
    const crossed = (ir.ir_thresholds ?? []).filter((t) => fromScore < t && score >= t);
    if (crossed.length > 0) {
      const threshold = Math.max(...crossed);
      await createItem(context, user, ir.id, 'score', `${await getName()} crossed score ${threshold}`, {
        ...itemBase,
        data: { from_score: fromScore, to_score: score, threshold, reasons: topReasons(rescore.result) },
      });
    }
  }
  return { ...rescore, becameVisible: visible && !wasVisible, dropped: false };
};

export const handleUpsertResult = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  result: UpsertMatchResult,
  criterionId: string,
  quiet = false,
  meta: IrChangeMeta = {},
  writer?: IrMatchWriter,
) => {
  return processMatchChange(context, user, ir, result.match, { created: result.created, previousStatus: result.previousStatus, criterionId, quiet, meta, writer });
};

const BACKFILL_MAX_ENTITIES = 2000;
const GROUPED_TOP = 5;

/**
 * One inbox item for the entities brought in at once by an entity that entered (backfill), instead of one per entity:
 * counts per type, how many reach the top threshold, and the best scored ones.
 */
const createGroupedEntryItem = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  root: { id: string; type: string },
  added: { id: string; type: string; score: number; excluded: boolean }[],
) => {
  const visible = added.filter((a) => !a.excluded);
  const byType = visible.reduce<Record<string, number>>((acc, a) => ({ ...acc, [a.type]: (acc[a.type] ?? 0) + 1 }), {});
  const top = Math.max(...(ir.ir_thresholds ?? [80]));
  const best = [...visible].sort((a, b) => b.score - a.score).slice(0, GROUPED_TOP);
  const bestNames = await Promise.all(best.map(async (a) => `${await entityDisplayName(context, user, a.id)} (${a.score})`));
  const rootMatch = await loadMatch(context, user, ir.id, root.id);
  const rootName = await entityDisplayName(context, user, root.id);
  await createItem(context, user, ir.id, 'entered', `${rootName} brought ${visible.length} entit${visible.length === 1 ? 'y' : 'ies'} into the requirement`, {
    entityId: root.id,
    entityType: root.type,
    matchId: rootMatch?.id,
    data: {
      message: `${Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, n]) => `${n} ${t}`).join(', ')}`
        + `${added.length > visible.length ? ` (${added.length - visible.length} not meeting the conditions of the scope)` : ''}`
        + ` · ${visible.filter((a) => a.score >= top).length} with a score of ${top} or more`,
      reasons: bestNames,
    },
  });
};

/**
 * Backfill: entities that just entered the requirement bring in what their existing relationships reach
 * through the second hop criteria, in cascade (an entity entering this way is backfilled too).
 */
export const backfillEnteredEntities = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  state: IrEngineState,
  entities: { id: string; type: string }[],
  at?: string, // date of the event that made the entities enter
  onSkipped?: () => void,
  writer?: IrMatchWriter,
) => {
  const queue = [...entities];
  const visited = new Set(queue.map((e) => e.id));
  let entered = 0;
  const added: { id: string; type: string; score: number; excluded: boolean }[] = [];
  while (queue.length > 0 && visited.size <= BACKFILL_MAX_ENTITIES) {
    const anchor = queue.shift()!;
    const candidates = await evaluateExistingRelationships(context, user, state, anchor);
    for (let i = 0; i < candidates.length; i += 1) {
      const candidate = candidates[i];
      const result = await upsertCandidate(context, user, ir, candidate, onSkipped);
      if (result) {
        const trigger = `${result.created ? 'Entered' : 'New proof'} through "${candidate.criterion.name}" (second hop)`;
        const { becameVisible, dropped, result: score } = await handleUpsertResult(context, user, ir, result, candidate.criterion.id, true, { at, trigger }, writer);
        if (dropped) state.inRequirement.delete(candidate.entity.id);
        if (result.created && !dropped && isIn(result.match.match_status)) {
          added.push({ id: candidate.entity.id, type: candidate.entity.type, score: score.score, excluded: score.excluded });
        }
        if (becameVisible) {
          entered += 1;
          state.inRequirement.add(candidate.entity.id);
          if (!visited.has(candidate.entity.id)) {
            visited.add(candidate.entity.id);
            queue.push(candidate.entity);
          }
        }
      }
    }
  }
  if (added.length > 0) await createGroupedEntryItem(context, user, ir, entities[0], added);
  return entered;
};

/**
 * Re-evaluate every entity of the requirement (after a change of its configuration or of a path condition fact).
 * The entities that become part of the requirement bring what they reach through the second hop criteria.
 */
export const rescoreRequirement = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, meta: IrChangeMeta = {}) => {
  const matches = await listMatches(context, user, ir.id, ['auto', 'accepted', 'proposed']);
  const entered: { id: string; type: string }[] = [];
  for (let i = 0; i < matches.length; i += 1) {
    const { becameVisible } = await processMatchChange(context, user, ir, matches[i], { meta });
    if (becameVisible) entered.push({ id: matches[i].match_entity_id, type: matches[i].match_entity_type });
  }
  // Many entities may have entered or left: the starting points of the second hop are read again
  invalidateInRequirementEntityIds(ir.id);
  if (entered.length > 0) {
    const state = await buildEngineState(context, SYSTEM_USER, ir);
    for (let i = 0; i < entered.length; i += 1) {
      await backfillEnteredEntities(context, SYSTEM_USER, ir, state, [entered[i]], meta.at);
    }
  }
  return matches.length;
};

/**
 * Entities stored before candidates were checked against the conditions of the scope, that do not meet them:
 * automatic and proposed ones leave the requirement (accepted ones stay, the analyst decided).
 */
export const purgeNotEligibleMatches = async (context: AuthContext, user: AuthUser, irId: string) => {
  const matches = (await listMatches(context, user, irId, LEAVES_WHEN_NOT_ELIGIBLE)).filter((m) => m.match_excluded);
  for (let i = 0; i < matches.length; i += 1) {
    await closeOpenItemsOfMatch(context, user, irId, matches[i].id, NOT_ELIGIBLE_RESULT);
    await deleteMatch(context, user, matches[i].id);
  }
  return matches.length;
};

// region analyst decisions
const MATCH_STATUS_RESULTS: Record<string, string> = {
  accepted: 'Accepted into the requirement',
  rejected: 'Rejected',
  removed: 'Removed from the requirement',
};

export const setMatchStatus = async (context: AuthContext, user: AuthUser, matchId: string, status: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  if (!MATCH_STATUS_RESULTS[status]) throw FunctionalError('Unsupported status', { status });
  const match = await loadMatchById(context, user, matchId);
  if (!match) throw FunctionalError('Entity of the requirement not found', { matchId });
  const updated = await updateMatchStatus(context, user, matchId, status);
  invalidateInRequirementEntityIds(match.ir_id);
  await closeOpenItemsOfMatch(context, user, match.ir_id, matchId, MATCH_STATUS_RESULTS[status]);
  if (status === 'accepted') {
    const ir = await storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, user, match.ir_id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
    if (ir) {
      const parsed = parseIntelligenceRequirement(ir);
      const { becameVisible } = await processMatchChange(context, user, parsed, updated, {
        previousStatus: match.match_status,
        meta: { kind: 'decision', trigger: `Accepted by ${user.name}` },
      });
      // Backfill: what the accepted entity already reaches through the second hop criteria (engine side, system user)
      if (becameVisible) {
        const state = await buildEngineState(context, SYSTEM_USER, parsed);
        await backfillEnteredEntities(context, SYSTEM_USER, parsed, state, [{ id: match.match_entity_id, type: match.match_entity_type }]);
      }
    }
  } else {
    await appendMatchHistory(context, user, updated, { status, kind: 'decision', trigger: `${MATCH_STATUS_RESULTS[status]} by ${user.name}` });
  }
  return updated;
};

// A decision applies to the entities in this status
const MATCH_DECISION_FROM: Record<string, string[]> = {
  accepted: ['proposed'],
  rejected: ['proposed'],
  removed: ['auto', 'accepted'],
};

/**
 * Mass operation on the entities of a requirement (entities list), one after the other.
 */
export const setMatchesStatus = async (context: AuthContext, user: AuthUser, matchIds: string[], status: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  let decided = 0;
  for (let i = 0; i < matchIds.length; i += 1) {
    const match = await loadMatchById(context, user, matchIds[i]);
    if (match && (MATCH_DECISION_FROM[status] ?? []).includes(match.match_status)) {
      await setMatchStatus(context, user, match.id, status);
      decided += 1;
    }
  }
  return decided;
};

const DECISION_STATUSES: Record<string, string> = { accept: 'accepted', reject: 'rejected', remove: 'removed' };

export const decideItem = async (context: AuthContext, user: AuthUser, itemId: string, decision: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const item = await storeLoadById<BasicStoreEntityIntelligenceRequirementItem>(context, user, itemId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM);
  if (!item) throw FunctionalError('Inbox item not found', { itemId });
  if (decision === 'acknowledge') return closeItem(context, user, itemId, 'Seen');
  const status = DECISION_STATUSES[decision];
  if (!status || !item.item_match_id) throw FunctionalError('Unsupported decision for this item', { itemId, decision });
  await setMatchStatus(context, user, item.item_match_id, status);
  return storeLoadById<BasicStoreEntityIntelligenceRequirementItem>(context, user, itemId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM);
};
// Decisions that apply to each kind of inbox item
export const IR_ITEM_DECISIONS: Record<string, string[]> = {
  proposed: ['accept', 'reject'],
  entered: ['acknowledge', 'remove'],
  score: ['acknowledge'],
  health: ['acknowledge'],
  brief: ['acknowledge'],
};

/**
 * Mass operation: the same decision on several inbox items, one after the other.
 * Closed items and items the decision does not apply to are skipped.
 */
export const decideItems = async (context: AuthContext, user: AuthUser, itemIds: string[], decision: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  let decided = 0;
  for (let i = 0; i < itemIds.length; i += 1) {
    const item = await storeLoadById<BasicStoreEntityIntelligenceRequirementItem>(context, user, itemIds[i], ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM);
    if (item && item.item_status === 'open' && (IR_ITEM_DECISIONS[item.item_kind] ?? []).includes(decision)) {
      await decideItem(context, user, item.id, decision);
      decided += 1;
    }
  }
  return decided;
};
// endregion
