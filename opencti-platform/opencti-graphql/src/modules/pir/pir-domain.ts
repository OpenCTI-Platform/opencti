import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR } from './pir-types';
import { type PirAddInput } from '../../generated/graphql';
import { createEntity } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { deleteInternalObject } from '../../domain/internalObject';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPIR>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

const PIR_RESCAN_PERIOD = 30 * 24 * 3600 * 1000; // 1 month in milliseconds

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  // -- create PIR --
  const finalInput = {
    ...input,
    pirCriteria: input.pirCriteria.map((c) => ({
      ...c,
      id: uuidv4(),
    })),
    // lastEventId: PIR_rescan_period before the effective last event id // TODO PIR
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
  // -- notify the PIR creation --
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};

export const deletePir = (context: AuthContext, user: AuthUser, pirId: string) => {
  // TODO PIR remove pir id from historic events
  return deleteInternalObject(context, user, pirId, ENTITY_TYPE_PIR);
};
