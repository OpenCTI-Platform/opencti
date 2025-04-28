import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR } from './pir-types';
import type { PirAddInput } from '../../generated/graphql';
import { createEntity } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  const created = await createEntity(
    context,
    user,
    input,
    ENTITY_TYPE_PIR,
  );
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates PIR \`${created.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_PIR, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};
