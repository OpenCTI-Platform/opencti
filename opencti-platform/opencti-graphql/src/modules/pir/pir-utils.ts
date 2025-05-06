import type { BasicStoreEntityPIR, PirDependency } from './pir-types';
import type { AuthContext } from '../../types/user';
import { listRelationsPaginated } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { stixRefRelationshipEditField } from '../../domain/stixRefRelationship';
import { FunctionalError } from '../../config/errors';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { stixObjectOrRelationshipAddRefRelation } from '../../domain/stixObjectOrStixRelationship';

export const computePirScore = (pir: BasicStoreEntityPIR, dependencies: PirDependency[]) => {
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
 * @param pirId ID of the PIR matched by the entity.
 * @param pirDependencies The new dependencies.
 * @param operation The edit operation (add, replace, ...).
 */
export const updatePirDependencies = async (
  context: AuthContext,
  sourceId: string,
  pirId: string,
  pirDependencies: PirDependency[],
  operation?: string, // 'add' to add a new dependency, 'replace' by default
) => {
  const pirMetaRels = await listRelationsPaginated(context, SYSTEM_USER, RELATION_IN_PIR, { fromId: sourceId, toId: pirId, });
  if (pirMetaRels.edges.length !== 1) {
    // If < 1 then the meta relationship does not exist.
    // If > 1, well this case should not be possible at all.
    throw FunctionalError('Find more than one relation between an entity and a PIR', { sourceId, pirId, pirMetaRels });
  }
  const pirMetaRel = pirMetaRels.edges[0].node;
  const editInput = [{ key: 'pir_dependencies', value: pirDependencies, operation }];
  const updatedRef = await stixRefRelationshipEditField(context, SYSTEM_USER, pirMetaRel.id, editInput);
  console.log('REF', updatedRef);
};

/**
 * Flag the source of the relationship by creating a meta relationship 'in-pir'
 * between the source and the PIR.
 *
 * @param context To be able to create the relationship.
 * @param sourceId ID of the source of the rel.
 * @param pirId ID of the PIR.
 * @param pirDependencies Criteria matched by the relationship.
 */
export const flagSource = async (
  context: AuthContext,
  sourceId: string,
  pirId: string,
  pirDependencies: PirDependency[],
) => {
  const addRefInput = {
    relationship_type: RELATION_IN_PIR,
    toId: pirId,
    pir_dependencies: pirDependencies,
  };
  // First create the meta relationship.
  await stixObjectOrRelationshipAddRefRelation(
    context,
    SYSTEM_USER,
    sourceId,
    addRefInput,
    ABSTRACT_STIX_CORE_OBJECT,
  );
  // And then add the dependencies in the meta relationship.
  // TODO PIR: improve this if possible to avoid making 2 calls.
  await updatePirDependencies(context, sourceId, pirId, pirDependencies);
};
