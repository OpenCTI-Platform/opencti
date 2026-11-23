import type { AuthContext } from '../../types/user';
import { pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { createRelation, deleteRelationsByFromAndTo, patchAttribute } from '../../database/middleware';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';
import { SYSTEM_USER } from '../../utils/access';
import { lockResources } from '../../lock/master-lock';
import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR, type PirExplanation } from '../pir/pir-types';
import { updatePirInformationOnEntity } from '../pir/pir-utils';
import type { ParsedIntelligenceRequirement } from './intelligenceRequirement-types';
import { type BasicStoreEntityIntelligenceRequirementMatch, isInRequirement } from './intelligenceRequirementMatch-types';
import { parseMatchExplanations } from './intelligenceRequirementMatch-domain';
import { legacyCriterionId, legacyPirScore } from './intelligenceRequirement-legacy';

// Projection of a requirement onto the Pir it drives (ir_pir_id): the legacy public contract stays written.
// An entity part of the requirement holds one in-pir relationship to the Pir, with pir_explanation and pir_score,
// and pir_information on the entity; an entity that leaves loses both. The writes are the ones the legacy engine makes
// (createPirRelation, updatePirExplanations, pirUnflagElement), so the stream events of in-pir keep their shape:
// the "Listen PIR events" playbook entry, the triggers on pir_score and the XTM One listener see nothing new.

const criterionIndex = (criterionId: string, count: number) => {
  for (let i = 0; i < count; i += 1) {
    if (legacyCriterionId(i) === criterionId) return i;
  }
  return -1;
};

/**
 * The legacy explanations of an entity of the requirement: one per proof of a criterion that comes from a legacy criterion
 * of the Pir, the criterion written as the Pir stores it (filters serialized, weight).
 */
export const matchToPirExplanations = (pir: Pick<BasicStoreEntityPir, 'pir_criteria'>, match: BasicStoreEntityIntelligenceRequirementMatch): PirExplanation[] => {
  const criteria = pir.pir_criteria ?? [];
  const byCriterion = new Map<number, PirExplanation>();
  parseMatchExplanations(match).forEach((explanation) => {
    const index = criterionIndex(explanation.criterion_id, criteria.length);
    if (index < 0) return;
    const current = byCriterion.get(index) ?? { dependencies: [], criterion: { filters: criteria[index].filters, weight: criteria[index].weight } };
    const elementId = explanation.relationship_id ?? explanation.anchor_id;
    if (elementId && !current.dependencies.some((d) => d.element_id === elementId)) {
      current.dependencies.push({ element_id: elementId, author_id: explanation.author_id ?? null });
    }
    byCriterion.set(index, current);
  });
  return Array.from(byCriterion.entries()).sort(([a], [b]) => a - b).map(([, e]) => e);
};

/**
 * A serialized filter group with its keys sorted, so two writings of the same criterion compare equal
 * (the legacy engine stores the criterion as the manager serialized it, the Pir as it was created).
 */
export const canonicalPirFilters = (filters: string) => {
  const sortKeys = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sortKeys);
    if (value && typeof value === 'object') {
      return Object.keys(value as Record<string, unknown>).sort().reduce((acc, key) => {
        acc[key] = sortKeys((value as Record<string, unknown>)[key]);
        return acc;
      }, {} as Record<string, unknown>);
    }
    return value;
  };
  try {
    return JSON.stringify(sortKeys(JSON.parse(filters)));
  } catch {
    return filters;
  }
};

const explanationKeys = (explanations: PirExplanation[]) => {
  const keys = new Map<string, Set<string>>();
  explanations.forEach((e) => {
    const key = `${canonicalPirFilters(e.criterion.filters)}#${e.criterion.weight}`;
    const deps = keys.get(key) ?? new Set<string>();
    e.dependencies.forEach((d) => deps.add(`${d.element_id}|${d.author_id ?? ''}`));
    keys.set(key, deps);
  });
  return keys;
};

/**
 * Same legacy explanations whatever their order, the order of their dependencies and the key order of the criterion filters.
 */
export const samePirExplanations = (a: PirExplanation[], b: PirExplanation[]) => {
  const keysA = explanationKeys(a);
  const keysB = explanationKeys(b);
  if (keysA.size !== keysB.size) return false;
  return Array.from(keysA.entries()).every(([key, deps]) => {
    const other = keysB.get(key);
    return !!other && other.size === deps.size && Array.from(deps).every((d) => other.has(d));
  });
};

/**
 * The legacy score of an entity of the requirement: the weights of the legacy criteria it matched over the sum of every weight.
 */
export const matchToPirScore = (pir: Pick<BasicStoreEntityPir, 'pir_criteria'>, match: BasicStoreEntityIntelligenceRequirementMatch) => {
  const weights = (pir.pir_criteria ?? []).map((c) => c.weight);
  return legacyPirScore(weights, match.match_criteria_ids ?? []);
};

const loadDrivenPir = async (context: AuthContext, ir: Pick<ParsedIntelligenceRequirement, 'ir_pir_id'>) => {
  if (!ir.ir_pir_id) return null;
  const pir = await storeLoadById<BasicStoreEntityPir>(context, SYSTEM_USER, ir.ir_pir_id, ENTITY_TYPE_PIR);
  return pir ?? null;
};

const withLock = async <T>(lockIds: string[], fn: () => Promise<T>) => {
  const lock = await lockResources(lockIds);
  try {
    return await fn();
  } finally {
    await lock.unlock();
  }
};

const unflag = async (context: AuthContext, entityId: string, pirId: string) => {
  await deleteRelationsByFromAndTo(context, SYSTEM_USER, entityId, pirId, RELATION_IN_PIR, ABSTRACT_STIX_REF_RELATIONSHIP);
  // pir_information is written in place (no stream event): a score of 0 removes the entry of this Pir
  await updatePirInformationOnEntity(context, SYSTEM_USER, entityId, pirId, 0);
};

/**
 * Write the state of an entity of the requirement onto the Pir: flag (create or patch in-pir) when it is part of
 * the requirement and matched at least one legacy criterion, unflag otherwise. No write when nothing changed.
 * Returns what was done (for tests and logs).
 */
export const projectMatchOnPir = async (
  context: AuthContext,
  ir: Pick<ParsedIntelligenceRequirement, 'ir_pir_id'>,
  match: BasicStoreEntityIntelligenceRequirementMatch,
): Promise<'none' | 'created' | 'updated' | 'deleted' | 'unchanged'> => {
  const pir = await loadDrivenPir(context, ir);
  if (!pir) return 'none';
  const entityId = match.match_entity_id;
  const lockIds = [entityId, pir.id];
  return withLock(lockIds, async () => {
    const rels = await pageRelationsConnection<BasicStoreRelationPir>(context, SYSTEM_USER, RELATION_IN_PIR, { fromId: entityId, toId: pir.id });
    const existing = rels.edges.length > 0 ? rels.edges[0].node : null;
    const explanations = isInRequirement(match) ? matchToPirExplanations(pir, match) : [];
    if (explanations.length === 0) {
      if (!existing) return 'unchanged';
      await unflag(context, entityId, pir.id);
      return 'deleted';
    }
    const pir_score = matchToPirScore(pir, match);
    if (!existing) {
      const input = { relationship_type: RELATION_IN_PIR, fromId: entityId, toId: pir.id, pir_explanation: explanations, pir_score };
      await createRelation(context, SYSTEM_USER, input, { locks: lockIds });
      await updatePirInformationOnEntity(context, SYSTEM_USER, entityId, pir.id, pir_score);
      return 'created';
    }
    const sameScore = existing.pir_score === pir_score;
    const sameExplanations = samePirExplanations(existing.pir_explanation ?? [], explanations);
    if (sameScore && sameExplanations) return 'unchanged';
    await patchAttribute(context, SYSTEM_USER, existing.id, RELATION_IN_PIR, { pir_explanation: explanations, pir_score }, { locks: lockIds });
    await updatePirInformationOnEntity(context, SYSTEM_USER, entityId, pir.id, pir_score);
    return 'updated';
  });
};

/**
 * An entity whose match is deleted (it left the requirement): its in-pir flag and pir_information for the Pir go too.
 */
export const unprojectMatchFromPir = async (
  context: AuthContext,
  ir: Pick<ParsedIntelligenceRequirement, 'ir_pir_id'>,
  match: Pick<BasicStoreEntityIntelligenceRequirementMatch, 'match_entity_id'>,
) => {
  const pir = await loadDrivenPir(context, ir);
  if (!pir) return false;
  await withLock([match.match_entity_id, pir.id], () => unflag(context, match.match_entity_id, pir.id));
  return true;
};
