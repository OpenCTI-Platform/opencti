import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type ParsedPIR, type PirDependency } from './pir-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { FunctionalError } from '../../config/errors';
import { createRelation, patchAttribute } from '../../database/middleware';

/**
 * Helper function to parse filters that are saved as string in elastic.
 *
 * @param pir The PIR to parse.
 * @returns PIR with parsed filters.
 */
export const parsePir = (pir: BasicStoreEntityPIR): ParsedPIR => {
  return {
    ...pir,
    pirFilters: JSON.parse(pir.pirFilters),
    pirCriteria: pir.pirCriteria.map((c) => ({
      ...c,
      filters: JSON.parse(c.filters),
    })),
  };
};

export const computePirScore = async (context: AuthContext, user: AuthUser, pirId: string, dependencies: PirDependency[]) => {
  const pir = await storeLoadById<BasicStoreEntityPIR>(context, user, pirId, ENTITY_TYPE_PIR);
  const maxScore = pir.pirCriteria.reduce((acc, val) => acc + val.weight, 0);
  const depScore = dependencies.reduce((acc, val) => acc + val.criterion.weight, 0);
  if (maxScore <= 0) return 0;
  return Math.round((depScore / maxScore) * 100);
};

/**
 * Find a meta relationship "in-pir" between an entity and a PIR and update
 * its dependencies (matching criteria).
 *
 * @param context To be able to make the calls.
 * @param sourceId ID of the source entity matching the PIR.
 * @param pir The PIR matched by the entity.
 * @param pirDependencies The new dependencies.
 * @param operation The edit operation (add, replace, ...).
 */
export const updatePirDependencies = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirDependencies: PirDependency[],
  operation?: string, // 'add' to add a new dependency, 'replace' by default
) => {
  const pirMetaRels = await listRelationsPaginated(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pirId, });
  if (pirMetaRels.edges.length !== 1) {
    // If < 1 then the meta relationship does not exist.
    // If > 1, well this case should not be possible at all.
    throw FunctionalError('Find more than one relation between an entity and a PIR', { sourceId, pirId, pirMetaRels });
  }
  const pirMetaRel = pirMetaRels.edges[0].node;
  // region compute score
  const deps = operation === 'add' ? [...pirMetaRel.pir_dependencies, ...pirDependencies] : pirDependencies;
  const pir_score = await computePirScore(context, user, pirId, deps);
  await patchAttribute(context, user, pirMetaRel.id, RELATION_IN_PIR, { pir_dependencies: deps, pir_score });
};

/**
 * Flag the source of the relationship by creating a meta relationship 'in-pir'
 * between the source and the PIR.
 *
 * @param context To be able to create the relationship.
 * @param sourceId ID of the source of the rel.
 * @param pir The PIR.
 * @param pirDependencies Criteria matched by the relationship.
 */
export const createPirRel = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirDependencies: PirDependency[],
) => {
  const addRefInput = {
    relationship_type: RELATION_IN_PIR,
    fromId: sourceId,
    toId: pirId,
    pir_dependencies: pirDependencies,
    pir_score: await computePirScore(context, user, pirId, pirDependencies),
  };
  await createRelation(context, user, addRefInput);
};
