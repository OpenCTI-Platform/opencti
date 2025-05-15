import { now } from 'moment';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR } from './pir-types';
import { type EditInput, EditOperation, type PirAddInput, type PirDependencyAddInput } from '../../generated/graphql';
import { createEntity, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { deleteInternalObject } from '../../domain/internalObject';
import { registerConnectorForPir, unregisterConnectorForIngestion } from '../../domain/connector';
import type { BasicStoreCommon } from '../../types/store';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { PIR_MANAGER_USER } from '../../utils/access';
import { createPirRel, updatePirDependencies } from './pir-utils';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPIR>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

const PIR_RESCAN_PERIOD = 30 * 24 * 3600 * 1000; // 1 month in milliseconds
const TEST_PIR_RESCAN_PERIOD = 3600 * 1000; // 1h hour in milliseconds // TODO PIR

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  const rescanStartDate = now() - TEST_PIR_RESCAN_PERIOD; // rescan start date in seconds
  // -- create PIR --
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
  const pirId = created.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates PIR \`${created.name}\``,
    context_data: { id: pirId, entity_type: ENTITY_TYPE_PIR, input: finalInput },
  });
  // create rabbit queue for pir
  await registerConnectorForPir(context, { id: pirId, ...finalInput });
  // -- notify the PIR creation --
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};

export const deletePir = async (context: AuthContext, user: AuthUser, pirId: string) => {
  // TODO PIR remove pir id from historic events
  // remove rabbit queue
  await unregisterConnectorForIngestion(context, pirId);
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
   * @param relationship The caught relationship matching the PIR.
   * @param pir The PIR matched by the relationship.
   * @param matchingCriteria The criteria that match.
   */
export const addPirDependency = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: PirDependencyAddInput,
) => {
  const { relationshipId, sourceId, matchingCriteria } = input;
  const source = await internalLoadById<BasicStoreCommon>(context, PIR_MANAGER_USER, sourceId);
  if (source) { // if element still exist
    const sourceFlagged = (source[RELATION_IN_PIR] ?? []).includes(pirId);
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
      await updatePirDependencies(context, user, sourceId, pirId, pirDependencies, EditOperation.Add);
      console.log('[POC PIR] Meta Ref relation updated');
    } else {
      console.log('[POC PIR] Source NOT flagged');
      await createPirRel(context, user, sourceId, pirId, pirDependencies);
      console.log('[POC PIR] Meta Ref relation created');
    }
  }
  return pirId;
};
