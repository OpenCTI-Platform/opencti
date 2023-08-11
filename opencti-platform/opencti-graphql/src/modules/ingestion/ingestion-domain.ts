import { BasicStoreEntityIngestion, ENTITY_TYPE_INGESTION } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, IngestionAddInput } from '../../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestion>(context, user, ingestionId, ENTITY_TYPE_INGESTION);
};

export const findAllPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listEntitiesPaginated<BasicStoreEntityIngestion>(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION], opts);
};

export const findAllIngestions = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listAllEntities<BasicStoreEntityIngestion>(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION], opts);
};

export const addIngestion = async (context: AuthContext, user: AuthUser, input: IngestionAddInput) => {
  const data = { ...input, running: false };
  const { element, isCreation } = await createEntity(context, user, data, ENTITY_TYPE_INGESTION, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION, input: data }
    });
  }
  return element;
};

export const patchIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION, patch);
  return patched.element;
};

export const ingestionEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION, input }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const ingestionDelete = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION, input: deleted }
  });
  return ingestionId;
};
