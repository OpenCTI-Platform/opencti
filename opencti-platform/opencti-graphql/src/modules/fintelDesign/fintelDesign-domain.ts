import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN } from './fintelDesign-types';
import type { EditInput, FintelDesignAddInput } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { BUS_TOPICS } from '../../config/conf';
import { notify } from '../../database/redis';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityFintelDesign> => {
  return storeLoadById(context, user, id, ENTITY_TYPE_FINTEL_DESIGN);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityFintelDesign>) => {
  return listEntitiesPaginated<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], opts);
};

export const addFintelDesign = async (context: AuthContext, user: AuthUser, fintelDesign: FintelDesignAddInput) => {
  const created = await createEntity(context, user, fintelDesign, ENTITY_TYPE_FINTEL_DESIGN);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates fintel design '${fintelDesign.name}`,
    context_data: {
      id: created.id,
      entity_type: ENTITY_TYPE_FINTEL_DESIGN,
      input: fintelDesign,
    },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].ADDED_TOPIC, created, user);
};

export const fintelDesignEditField = async (
  context: AuthContext,
  user: AuthUser,
  designId: string,
  input: EditInput[],
) => {
  const { element } = await updateAttribute(context, user, designId, ENTITY_TYPE_FINTEL_DESIGN, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates ${input.map((i) => i.key).join(', ')} for fintel design ${element.name}`,
    context_data: {
      id: element.id,
      entity_type: ENTITY_TYPE_FINTEL_DESIGN,
      input,
    }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].EDIT_TOPIC, element, user);
};

export const fintelDesignDelete = async (context: AuthContext, user: AuthUser, designId: string) => {
  const deleted = await deleteElementById(
    context,
    user,
    designId,
    ENTITY_TYPE_FINTEL_DESIGN,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes fintel design \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_FINTEL_DESIGN,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].DELETE_TOPIC, deleted, user).then(() => designId);
};
