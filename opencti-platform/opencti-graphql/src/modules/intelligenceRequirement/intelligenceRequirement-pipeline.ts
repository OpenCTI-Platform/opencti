import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, type ParsedIntelligenceRequirement } from './intelligenceRequirement-types';
import { type BasicStoreEntityIntelligenceRequirementMatch, IR_MATCH_IN_STATUSES } from './intelligenceRequirementMatch-types';
import { type BasicStoreEntityIntelligenceRequirementItem, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from './intelligenceRequirementItem-types';
import { listMatches, loadMatch, loadMatchById, updateMatchStatus, upsertMatch, type UpsertMatchResult } from './intelligenceRequirementMatch-domain';
import { buildEngineState, evaluateExistingRelationships, type IrEngineState } from './intelligenceRequirement-engine';
import { SYSTEM_USER } from '../../utils/access';
import { rescoreMatch, topReasons } from './intelligenceRequirement-scoring';
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
}

const isIn = (status: string) => IR_MATCH_IN_STATUSES.includes(status);

/**
 * Rescore an entity of the requirement, then create the inbox items implied by the change:
 * - proposed: a new entity proposed by a criterion in Propose mode
 * - entered: an entity that becomes part of the requirement automatically (or now meets the required rules)
 * - score: a threshold crossed upward (from 0 when the entity just became part of the requirement)
 * Entities excluded by a required rule produce no item.
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
  const wasVisible = !change.created && isIn(previousStatus) && !(match.match_excluded ?? false);
  const rescore = await rescoreMatch(context, user, ir, match);
  const { excluded, score } = rescore.result;
  // Keep the in-memory match up to date: the engine reuses it for the next events of the batch
  Object.assign(match, { match_score: score, match_excluded: excluded });
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
  if (change.created && status === 'proposed' && !excluded) {
    await createItem(context, user, ir.id, 'proposed', `${await getName()} proposed`, { ...itemBase, data: { criterion_id: change.criterionId } });
  }
  if (visible && !wasVisible && status === 'auto' && !change.quiet) {
    const title = !change.created && isIn(previousStatus) ? `${await getName()} now meets the required rules` : `${await getName()} entered the requirement`;
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
  return rescore;
};

export const handleUpsertResult = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  result: UpsertMatchResult,
  criterionId: string,
  quiet = false,
) => {
  return processMatchChange(context, user, ir, result.match, { created: result.created, previousStatus: result.previousStatus, criterionId, quiet });
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
        + `${added.length > visible.length ? ` (${added.length - visible.length} excluded by a required rule)` : ''}`
        + ` · ${visible.filter((a) => a.score >= top).length} with a score of ${top} or more`,
      reasons: bestNames,
    },
  });
};

/**
 * True when the upsert made the entity part of the requirement (created in, or moved from proposed/out to in).
 */
export const hasEntered = (result: UpsertMatchResult) => isIn(result.match.match_status) && (result.created || !result.previousStatus || !isIn(result.previousStatus));

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
) => {
  const queue = [...entities];
  const visited = new Set(queue.map((e) => e.id));
  let entered = 0;
  const added: { id: string; type: string; score: number; excluded: boolean }[] = [];
  while (queue.length > 0 && visited.size <= BACKFILL_MAX_ENTITIES) {
    const anchor = queue.shift()!;
    state.inRequirement.add(anchor.id);
    const candidates = await evaluateExistingRelationships(context, user, state, anchor);
    for (let i = 0; i < candidates.length; i += 1) {
      const candidate = candidates[i];
      const result = await upsertMatch(context, user, ir.id, candidate.entity, candidate.criterion, candidate.explanation);
      if (result) {
        await handleUpsertResult(context, user, ir, result, candidate.criterion.id, true);
        if (hasEntered(result)) {
          entered += 1;
          added.push({ id: candidate.entity.id, type: candidate.entity.type, score: result.match.match_score ?? 0, excluded: result.match.match_excluded ?? false });
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
 * Rescore every entity of the requirement (after a change of its relevance rules or of a path condition fact).
 */
export const rescoreRequirement = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement) => {
  const matches = await listMatches(context, user, ir.id, ['auto', 'accepted', 'proposed']);
  for (let i = 0; i < matches.length; i += 1) {
    await processMatchChange(context, user, ir, matches[i]);
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
  await closeOpenItemsOfMatch(context, user, match.ir_id, matchId, MATCH_STATUS_RESULTS[status]);
  if (status === 'accepted') {
    const ir = await storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, user, match.ir_id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
    if (ir) {
      const parsed = parseIntelligenceRequirement(ir);
      await processMatchChange(context, user, parsed, updated, { previousStatus: match.match_status });
      // Backfill: what the accepted entity already reaches through the second hop criteria (engine side, system user)
      if (!isIn(match.match_status)) {
        const state = await buildEngineState(context, SYSTEM_USER, parsed);
        await backfillEnteredEntities(context, SYSTEM_USER, parsed, state, [{ id: match.match_entity_id, type: match.match_entity_type }]);
      }
    }
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
