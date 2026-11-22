import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { createEntity, patchAttribute } from '../../database/middleware';
import { logApp } from '../../config/conf';
import { SYSTEM_USER } from '../../utils/access';
import type { EditInput } from '../../generated/graphql';
import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR } from '../pir/pir-types';
import { parsePir } from '../pir/pir-utils';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT } from './intelligenceRequirement-types';
import { legacyCriterionId, legacyPirToRequirement } from './intelligenceRequirement-legacy';
import { intelligenceRequirementDelete } from './intelligenceRequirement-domain';
import type { BasicStoreEntityIntelligenceRequirementMatch, StoreIrMatchExplanation } from './intelligenceRequirementMatch-types';
import { canonicalPirFilters, matchToPirExplanations, matchToPirScore, samePirExplanations } from './intelligenceRequirement-projection';

// Link between a Pir and the intelligence requirement built from it (pir_requirement_id on the Pir, ir_pir_id on the requirement).
// The requirement is the only engine (opencti #20278): it flags the entities and projects them onto its Pir.
// The Pir write API (pirFieldPatch, pirEditAuthorizedMembers, pirDelete) is mirrored onto the requirement, so both stay in step.

// Fields of the Pir edit API that have a twin on the requirement
const MIRRORED_PIR_FIELDS: Record<string, string> = { name: 'name', description: 'description' };

/**
 * Stored attributes of the requirement that drives a Pir. Pure and deterministic: the same Pir builds the same requirement.
 * The stream position of the Pir is kept, so linking an existing Pir does not replay its rescan window.
 */
export const buildRequirementForPir = (pir: BasicStoreEntityPir) => {
  const parsed = parsePir(pir);
  const config = legacyPirToRequirement({
    name: pir.name,
    description: pir.description,
    pir_type: pir.pir_type,
    pir_rescan_days: pir.pir_rescan_days,
    pir_filters: parsed.pir_filters,
    pir_criteria: parsed.pir_criteria,
  });
  return {
    name: config.name,
    description: config.description,
    ir_question: config.ir_question,
    ir_priority: config.ir_priority,
    ir_status: config.ir_status,
    ir_kiqs: '[]',
    ir_subject_groups: JSON.stringify(config.ir_subject_groups),
    ir_scope_criteria: JSON.stringify(config.ir_scope_criteria),
    ir_relevance_rules: JSON.stringify(config.ir_relevance_rules),
    ir_thresholds: config.ir_thresholds,
    ir_rescan_days: config.ir_rescan_days,
    ir_brief_frequency: config.ir_brief_frequency,
    ir_pir_id: pir.id,
    lastEventId: pir.lastEventId,
    ir_processing: JSON.stringify({ catchup_from: pir.lastEventId }),
    // Same access as the Pir: a reader without access to the Pir has none to its requirement
    authorized_members: pir.restricted_members ?? [],
  };
};

/**
 * Create the requirement of a Pir and link both. Idempotent: a Pir already linked to an existing requirement returns it,
 * a link to a requirement that no longer exists is rebuilt (the migration and pirAdd both call it).
 */
export const linkPirToRequirement = async (context: AuthContext, pir: BasicStoreEntityPir, locks: string[] = []) => {
  if (pir.pir_requirement_id) {
    const existing = await storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, SYSTEM_USER, pir.pir_requirement_id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
    if (existing) return existing.id;
  }
  const now = new Date();
  const created = await createEntity(context, SYSTEM_USER, { ...buildRequirementForPir(pir), created_at: now, updated_at: now }, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
  await patchAttribute(context, SYSTEM_USER, pir.id, ENTITY_TYPE_PIR, { pir_requirement_id: created.internal_id }, { locks });
  return created.internal_id as string;
};

/**
 * pirAdd: the new Pir gets its requirement. A failure is logged and never fails the Pir creation (the Pir is the contract);
 * the link is rebuilt by the next call of linkPirToRequirement.
 */
export const linkNewPirToRequirement = async (context: AuthContext, pir: BasicStoreEntityPir) => {
  try {
    return await linkPirToRequirement(context, pir);
  } catch (err) {
    logApp.error('[OPENCTI-MODULE] Intelligence requirement not created for the new Pir', { cause: err, pir: pir.id });
    return null;
  }
};

const loadLinkedRequirement = async (context: AuthContext, pir: Pick<BasicStoreEntityPir, 'pir_requirement_id'> | null | undefined) => {
  if (!pir?.pir_requirement_id) return null;
  return storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, SYSTEM_USER, pir.pir_requirement_id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
};

/**
 * The edit inputs of a Pir that apply to its requirement (name, description); the stream position is never mirrored.
 */
export const mirroredRequirementPatch = (input: EditInput[]) => {
  const patch: Record<string, unknown> = {};
  input.forEach((i) => {
    const target = MIRRORED_PIR_FIELDS[i.key];
    if (target) patch[target] = Array.isArray(i.value) ? i.value[0] ?? '' : i.value;
  });
  return patch;
};

/**
 * pirFieldPatch: the name and description of a linked Pir are written on its requirement too.
 * A mirror failure is logged and never fails the Pir write (the Pir is the contract).
 */
export const mirrorPirPatchOnRequirement = async (context: AuthContext, pir: Pick<BasicStoreEntityPir, 'id' | 'pir_requirement_id'>, input: EditInput[]) => {
  const patch = mirroredRequirementPatch(input);
  if (Object.keys(patch).length === 0) return false;
  try {
    const requirement = await loadLinkedRequirement(context, pir);
    if (!requirement) return false;
    await patchAttribute(context, SYSTEM_USER, requirement.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, patch);
    return true;
  } catch (err) {
    logApp.error('[OPENCTI-MODULE] Pir patch not mirrored on its intelligence requirement', { cause: err, pir: pir.id });
    return false;
  }
};

/**
 * pirEditAuthorizedMembers: the requirement of a linked Pir gets the same members.
 */
export const mirrorPirMembersOnRequirement = async (context: AuthContext, pirId: string) => {
  try {
    const pir = await storeLoadById<BasicStoreEntityPir>(context, SYSTEM_USER, pirId, ENTITY_TYPE_PIR);
    const requirement = await loadLinkedRequirement(context, pir);
    if (!requirement) return false;
    await patchAttribute(context, SYSTEM_USER, requirement.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, { restricted_members: pir.restricted_members ?? [] });
    return true;
  } catch (err) {
    logApp.error('[OPENCTI-MODULE] Pir members not mirrored on its intelligence requirement', { cause: err, pir: pirId });
    return false;
  }
};

// ---------------------------------------------------------------------------------------------------------------------
// Conversion of legacy flags (used by the migration 1795536000000): an in-pir relationship becomes an entity of the
// requirement, and a parity check proves that its projection writes back the same pir_score and pir_explanation.

export interface PirParityMismatch {
  entity_id: string;
  stored_score: number;
  projected_score: number;
  same_explanations: boolean;
}

/**
 * The match an in-pir relationship becomes: one proof per dependency of each legacy explanation, on the criterion
 * the explanation was written for (found by its filters and weight). Pure.
 */
export const inPirRelationToMatch = (pir: Pick<BasicStoreEntityPir, 'pir_criteria'>, relation: Pick<BasicStoreRelationPir, 'fromId' | 'pir_explanation' | 'pir_score'>, at: string) => {
  const criteria = (pir.pir_criteria ?? []).map((c) => `${canonicalPirFilters(c.filters)}#${c.weight}`);
  const criteriaIds = new Set<string>();
  const explanations: StoreIrMatchExplanation[] = [];
  (relation.pir_explanation ?? []).forEach((legacy) => {
    const index = criteria.indexOf(`${canonicalPirFilters(legacy.criterion.filters)}#${legacy.criterion.weight}`);
    if (index < 0) return;
    const criterionId = legacyCriterionId(index);
    criteriaIds.add(criterionId);
    legacy.dependencies.forEach((dependency) => {
      explanations.push({ criterion_id: criterionId, kind: 'graph', at, relationship_id: dependency.element_id, author_id: dependency.author_id ?? null });
    });
  });
  return {
    match_criteria_ids: Array.from(criteriaIds),
    match_explanations: JSON.stringify(explanations),
    match_score: relation.pir_score ?? 0,
  };
};

/**
 * Parity of one flag: the match built from it projects back the stored score and explanations. Pure.
 */
export const checkInPirParity = (pir: Pick<BasicStoreEntityPir, 'pir_criteria'>, relation: BasicStoreRelationPir, at: string): PirParityMismatch | null => {
  const seed = inPirRelationToMatch(pir, relation, at);
  const match = { ...seed, match_status: 'auto', match_excluded: false } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
  const projectedScore = matchToPirScore(pir, match);
  const sameExplanations = samePirExplanations(relation.pir_explanation ?? [], matchToPirExplanations(pir, match));
  if (projectedScore === relation.pir_score && sameExplanations) return null;
  return { entity_id: relation.fromId, stored_score: relation.pir_score, projected_score: projectedScore, same_explanations: sameExplanations };
};

/**
 * pirDelete: the requirement of a linked Pir and everything stored for it go with the Pir.
 * Read before the Pir is deleted (the link is on the Pir).
 */
export const deleteRequirementOfPir = async (context: AuthContext, user: AuthUser, pir: Pick<BasicStoreEntityPir, 'id' | 'pir_requirement_id'> | null | undefined) => {
  const requirement = await loadLinkedRequirement(context, pir);
  if (!requirement) return false;
  await intelligenceRequirementDelete(context, SYSTEM_USER, requirement.id);
  logApp.info('[OPENCTI-MODULE] Intelligence requirement deleted with its Pir', { pir: pir?.id, requirement: requirement.id, user: user.id });
  return true;
};
