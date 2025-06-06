import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR, type ParsedPir, type PirExplanation } from './pir-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { FunctionalError } from '../../config/errors';
import { createRelation, patchAttribute } from '../../database/middleware';
import type { PirAddInput } from '../../generated/graphql';

/**
 * Helper function to parse filters that are saved as string in elastic.
 *
 * @param pir The Pir to parse.
 * @returns Pir with parsed filters.
 */
export const parsePir = (pir: BasicStoreEntityPir): ParsedPir => {
  return {
    ...pir,
    pir_filters: JSON.parse(pir.pir_filters),
    pir_criteria: pir.pir_criteria.map((c) => ({
      ...c,
      filters: JSON.parse(c.filters),
    })),
  };
};

/**
 * Helper function to parse filters that are saved as string in elastic.
 *
 * @param pir The Pir to parse.
 * @returns Pir with parsed filters.
 */
export const serializePir = (pir: PirAddInput) => {
  return {
    ...pir,
    pir_filters: JSON.stringify(pir.pir_filters),
    pir_criteria: pir.pir_criteria.map((c) => ({
      ...c,
      filters: JSON.stringify(c.filters),
    })),
  };
};

/**
 * Determines the score of an array of explanations against a PIR.
 *
 * @param context
 * @param user
 * @param pirId ID of the PIR to check the score.
 * @param explanations List of explanations used to compute score.
 * @returns An integer between 0 and 100.
 */
export const computePirScore = async (context: AuthContext, user: AuthUser, pirId: string, explanations: PirExplanation[]) => {
  const pir = await storeLoadById<BasicStoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR);
  const maxScore = pir.pir_criteria.reduce((acc, val) => acc + val.weight, 0);
  const depScore = explanations.reduce((acc, val) => acc + val.criterion.weight, 0);
  if (maxScore <= 0) return 0;
  return Math.round((depScore / maxScore) * 100);
};

/**
 * Determines if two explanations are identical or not.
 *
 * @param explanation1 First explanation.
 * @param explanation2 Second explanation.
 * @returns True if they are the same.
 */
export const arePirExplanationsEqual = (
  explanation1: PirExplanation,
  explanation2: PirExplanation
) => {
  const sameRelationships = explanation1.dependencies.map((d1) => d1.element_id)
    .every((d) => explanation2.dependencies.map((d2) => d2.element_id).includes(d));
  const sameCriteriaWeight = explanation1.criterion.weight === explanation2.criterion.weight;
  const sameCriteriaFilters = explanation1.criterion.filters === explanation2.criterion.filters;
  return sameRelationships && sameCriteriaWeight && sameCriteriaFilters;
};

/**
 * Compare an array of explanations with another array to kept only new explanations.
 *
 * @param explanations Array to filter.
 * @param baseExplanations Base array to make the comparison.
 * @returns A sub-array of the first argument containing only explanations that are not in the base array.
 */
export const diffPirExplanations = (
  explanations: PirExplanation[],
  baseExplanations: PirExplanation[]
) => {
  return explanations.filter((explanation) => {
    // For each explanation, check it is different from all explanations in base.
    return baseExplanations.every((e) => !arePirExplanationsEqual(explanation, e));
  });
};

/**
 * Find a meta relationship "in-pir" between an entity and a Pir and update
 * its explanations (matching criteria).
 *
 * @param context To be able to make the calls.
 * @param user User calling the request.
 * @param sourceId ID of the source entity matching the Pir.
 * @param pirId The if of the Pir matched by the entity.
 * @param pirExplanations The new explanations
 * @param operation The edit operation (add, replace, ...).
 */
export const updatePirExplanations = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirExplanations: PirExplanation[],
  operation?: string, // 'add' to add a new dependency, 'replace' by default
) => {
  const pirMetaRels = await listRelationsPaginated<BasicStoreRelationPir>(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pirId, });
  if (pirMetaRels.edges.length === 0) {
    // If = 0 then the meta relationship does not exist.
    throw FunctionalError('Relation between the entity and a Pir not found', { sourceId, pirId, pirMetaRels });
  }
  if (pirMetaRels.edges.length > 1) {
    // If > 1, well this case should not be possible at all.
    throw FunctionalError('Find more than one relation between an entity and a Pir', { sourceId, pirId, pirMetaRels });
  }

  const pirMetaRel = pirMetaRels.edges[0].node;
  let explanations = pirExplanations; // By default replace the entire array.
  if (operation === 'add') {
    const newExplanations = diffPirExplanations(pirExplanations, pirMetaRel.pir_explanations);
    if (newExplanations.length === 0) {
      // In this case there is nothing to add so skip.
      return;
    }
    explanations = [...pirMetaRel.pir_explanations, ...newExplanations];
  }

  // region compute score
  const pir_score = await computePirScore(context, user, pirId, explanations);
  // replace pir_explanations
  await patchAttribute(context, user, pirMetaRel.id, RELATION_IN_PIR, { pir_explanations: explanations, pir_score });
};

/**
 * Flag the source of the relationship by creating a meta relationship 'in-pir'
 * between the source and the PIR.
 *
 * @param context To be able to create the relationship.
 * @param user User calling the request.
 * @param sourceId ID of the source of the rel.
 * @param pirId The ID of the PIR.
 * @param pirDependencies Criteria matched by the relationship.
 */
export const createPirRel = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirDependencies: PirExplanation[],
) => {
  const addRefInput = {
    relationship_type: RELATION_IN_PIR,
    fromId: sourceId,
    toId: pirId,
    pir_explanations: pirDependencies,
    pir_score: await computePirScore(context, user, pirId, pirDependencies),
  };
  await createRelation(context, user, addRefInput);
};
