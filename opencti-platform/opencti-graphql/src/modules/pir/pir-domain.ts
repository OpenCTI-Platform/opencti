import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR } from './pir-types';
import type { PirAddInput } from '../../generated/graphql';
import { createEntity } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPIR>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  const finalInput = {
    ...input,
    pirCriteria: input.pirCriteria.map((c) => ({
      ...c,
      id: uuidv4(),
    }))
  };
  const created = await createEntity(
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
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};
