import { now } from 'moment';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, internalLoadById, listEntitiesPaginated, listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type PirDependency } from './pir-types';
import { type EditInput, EditOperation, type PirAddInput, type PirDependencyAddInput, type PirDependencyDeleteInput } from '../../generated/graphql';
import { createEntity, deleteRelationsByFromAndTo, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { deleteInternalObject } from '../../domain/internalObject';
import { registerConnectorForPir, unregisterConnectorForIngestion } from '../../domain/connector';
import type { BasicStoreCommon } from '../../types/store';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { createPirRel, updatePirDependencies } from './pir-utils';
import { FunctionalError } from '../../config/errors';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPIR>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

// const PIR_RESCAN_PERIOD = 30 * 24 * 3600 * 1000; // 1 month in milliseconds
const TEST_PIR_RESCAN_PERIOD = 3600 * 1000; // 1h hour in milliseconds // TODO PIR

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  // -- create PIR --
  const rescanStartDate = now() - TEST_PIR_RESCAN_PERIOD; // rescan start date in seconds
  const finalInput = {
    ...input,
    lastEventId: `${rescanStartDate}-0`,
  };
  const created: BasicStoreEntityPIR = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_PIR,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates PIR \`${created.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_PIR, input: finalInput },
  });
  // create rabbit queue for pir
  await registerConnectorForPir(context, { id: created.id, ...finalInput });
  // -- notify the PIR creation --
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};

export const deletePir = async (context: AuthContext, user: AuthUser, pirId: string) => {
  // TODO PIR remove pir id from historic events
  // remove rabbit queue
  try {
    await unregisterConnectorForIngestion(context, pirId);
  } catch (e) {
    logApp.error('[OPENCTI] Error while unregistering PIR connector', { cause: e });
  }
  // delete the PIR
  return deleteInternalObject(context, user, pirId, ENTITY_TYPE_PIR);
};

export const updatePir = async (context: AuthContext, user: AuthUser, pirId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, pirId, ENTITY_TYPE_PIR, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].EDIT_TOPIC, element, user);
};

/**
   * Called when an event of create new relationship matches a PIR criteria.
   * If the source of the relationship is already flagged update its dependencies,
   * otherwise create a new meta relationship between the source and the PIR.
   *
   * @param context To be able to call engine.
   * @param user User making the request.
   * @param pirId The ID of the PIR matched by the relationship.
   * @param input The data needed to create the dependency.
   */
export const addPirDependency = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: PirDependencyAddInput,
) => {
  const pir = await storeLoadById<BasicStoreEntityPIR>(context, user, pirId, ENTITY_TYPE_PIR);
  if (!pir) {
    throw FunctionalError('No PIR found');
  }

  const { relationshipId, sourceId, matchingCriteria } = input;
  const source = await internalLoadById<BasicStoreCommon>(context, user, sourceId);

  if (source) { // if element still exist
    const sourceFlagged = (source[RELATION_IN_PIR] ?? []).includes(pir.id);
    console.log('[POC PIR] Event create matching', { source, relationshipId, matchingCriteria });

    const pirDependencies = matchingCriteria.map((criterion) => ({
      relationship_id: relationshipId,
      criterion: {
        ...criterion,
        filters: JSON.stringify(criterion.filters)
      },
    }));
    if (sourceFlagged) {
      console.log('[POC PIR] Source already flagged');
      await updatePirDependencies(context, user, sourceId, pir.id, pirDependencies, EditOperation.Add);
      console.log('[POC PIR] Meta Ref relation updated');
    } else {
      console.log('[POC PIR] Source NOT flagged');
      await createPirRel(context, user, sourceId, pir.id, pirDependencies);
      console.log('[POC PIR] Meta Ref relation created');
    }
  }
  return pir.id;
};

/**
 * Called when an event of delete a relationship matches a PIR criteria.
 *
 * @param context To be able to call engine.
 * @param relationship The caught relationship matching the PIR.
 * @param pir The PIR matched by the relationship.
 */
export const deletePirDependency = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: PirDependencyDeleteInput,
) => {
  const pir = await storeLoadById<BasicStoreEntityPIR>(context, user, pirId, ENTITY_TYPE_PIR);
  if (!pir) {
    throw FunctionalError('No PIR found');
  }
  const { relationshipId, sourceId } = input;
  console.log('[POC PIR] Event delete matching', { relationshipId, pirId });
  // fetch rel between object and pir
  const rels = await listRelationsPaginated(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pir.id }); // TODO PIR don't use pagination
  // eslint-disable-next-line no-restricted-syntax
  for (const rel of rels.edges) {
    const relDependencies = (rel as any).node.pir_dependencies as PirDependency[];
    const newRelDependencies = relDependencies.filter((dep) => dep.relationship_id !== relationshipId);
    if (newRelDependencies.length === 0) {
      // delete the rel between source and PIR
      await deleteRelationsByFromAndTo(context, user, sourceId, pir.id, RELATION_IN_PIR, ABSTRACT_STIX_REF_RELATIONSHIP); // TODO PIR not working
      console.log('[POC PIR] PIR rel deleted');
    } else if (newRelDependencies.length < relDependencies.length) {
      // update dependencies
      await updatePirDependencies(context, user, sourceId, pir.id, newRelDependencies);
      console.log('[POC PIR] PIR rel updated', { newRelDependencies });
    } // nothing to do
  }
  return pir.id;
};
