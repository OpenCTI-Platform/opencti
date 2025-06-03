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

export const computePirScore = async (context: AuthContext, user: AuthUser, pirId: string, dependencies: PirExplanation[]) => {
  const pir = await storeLoadById<BasicStoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR);
  const maxScore = pir.pir_criteria.reduce((acc, val) => acc + val.weight, 0);
  const depScore = dependencies.reduce((acc, val) => acc + val.criterion.weight, 0);
  if (maxScore <= 0) return 0;
  return Math.round((depScore / maxScore) * 100);
};

// check explanations are contains in the pir explanations
// Note that we don't handle the case where dependency_ids contains several relationship ids (this case is not possible for the moment)
export const isPirExplanationsInMetaRel = (
  pirMetaRelExplanations: PirExplanation[],
  explanations: PirExplanation[],
) => {
  return explanations
    .every((explanation) => pirMetaRelExplanations
      .some((pirExplanation) => explanation.dependency_ids.every((d) => pirExplanation.dependency_ids.includes(d))
        && pirExplanation.criterion.weight === explanation.criterion.weight
        && pirExplanation.criterion.filters === explanation.criterion.filters));
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
  const relationshipUpdateAlreadyFlagged = operation === 'add' && isPirExplanationsInMetaRel(pirMetaRel.pir_explanations, pirExplanations); // case update relationship with source already flagged for it
  if (!relationshipUpdateAlreadyFlagged) {
    // region compute score
    const deps = operation === 'add' ? [...pirMetaRel.pir_explanations, ...pirExplanations] : pirExplanations;
    const pir_score = await computePirScore(context, user, pirId, deps);
    // replace pir_explanations
    await patchAttribute(context, user, pirMetaRel.id, RELATION_IN_PIR, { pir_explanations: deps, pir_score });
  }
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
