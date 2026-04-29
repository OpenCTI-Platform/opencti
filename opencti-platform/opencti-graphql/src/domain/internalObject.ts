import type { AuthContext, AuthUser } from '../types/user';
import type { StoreEntity } from '../types/store';
import { createEntity, deleteElementById, updateAttribute } from '../database/middleware';
import { publishUserAction } from '../listener/UserActionListener';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS, getBusTopicForEntityType } from '../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import type { EditInput, EditContext } from '../generated/graphql';
import { FunctionalError } from '../config/errors';
import { storeLoadById } from '../database/middleware-loader';

const humanReadableFormatEntityType = (entityType: string) => {
  return entityType.replace(/([A-Z])/g, ' $1').trim();
};

export const createInternalObject = async <T extends StoreEntity>(
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  entityType: string,
  opts: {
    auditLogEnabled?: boolean;
    auditLogContextSanitizer?: (input: Record<string, unknown>) => Record<string, unknown>;
  } = {},
): Promise<T> => {
  const { element, isCreation } = await createEntity(context, user, input, entityType, { complete: true });
  const { auditLogEnabled = true } = opts;
  if (isCreation && auditLogEnabled) {
    const sanitizedContextInput = opts?.auditLogContextSanitizer?.(input) ?? input;
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates ${humanReadableFormatEntityType(entityType)} \`${element.name}\``,
      context_data: { id: element.id, entity_type: element.entity_type, input: sanitizedContextInput },
    });
  }
  const notifyTopic = getBusTopicForEntityType(entityType)?.ADDED_TOPIC ?? BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC;
  return notify(notifyTopic, element, user);
};

export const editInternalObject = async <T extends StoreEntity>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  entityType: string,
  input: EditInput[],
  opts: {
    auditLogEnabled?: boolean;
    auditLogContextSanitizer?: (input: EditInput[]) => EditInput[];
  } = {},
): Promise<T> => {
  const internalObject = await storeLoadById(context, user, id, entityType);
  if (!internalObject) {
    throw FunctionalError(`${entityType} ${id} cant be found`);
  }
  const { element } = await updateAttribute<StoreEntity>(context, user, id, entityType, input);
  const { auditLogEnabled = true } = opts;
  if (auditLogEnabled) {
    const sanitizedContextInput = opts?.auditLogContextSanitizer?.(input) ?? input;
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `updates \`${input.map((i) => i.key).join(', ')}\` for ${humanReadableFormatEntityType(entityType)} \`${element.name}\``,
      context_data: { id, entity_type: entityType, input: sanitizedContextInput },
    });
  }
  const notifyTopic = getBusTopicForEntityType(entityType)?.EDIT_TOPIC ?? BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC;
  return notify(notifyTopic, element, user);
};

export const deleteInternalObject = async <T extends StoreEntity>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  entityType: string,
  opts: {
    auditLogEnabled?: boolean;
    auditLogContextSanitizer?: (input: T) => Record<string, unknown>;
  } = {},
) => {
  const internalObject = await storeLoadById(context, user, id, entityType);
  if (!internalObject) {
    throw FunctionalError(`${entityType} ${id} cant be found`);
  }
  const deleted = await deleteElementById<T>(context, user, id, entityType);
  const { auditLogEnabled = true } = opts;
  if (auditLogEnabled) {
    const sanitizedContextInput = opts?.auditLogContextSanitizer?.(deleted) ?? deleted;
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: `deletes ${humanReadableFormatEntityType(entityType)} \`${deleted.name}\``,
      context_data: { id, entity_type: entityType, input: sanitizedContextInput },
    });
  }
  const notifyTopic = getBusTopicForEntityType(entityType)?.DELETE_TOPIC ?? BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC;
  await notify(notifyTopic, internalObject, user);
  return id;
};

export const internalObjectCleanContext = async (context: AuthContext, user: AuthUser, internalObjectId: string) => {
  await delEditContext(user, internalObjectId);
  return storeLoadById(context, user, internalObjectId, ABSTRACT_INTERNAL_OBJECT).then((internalObject) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].CONTEXT_TOPIC, internalObject, user);
  });
};

export const internalObjectEditContext = async (context: AuthContext, user: AuthUser, internalObjectId: string, input: EditContext) => {
  await setEditContext(user, internalObjectId, input);
  return storeLoadById(context, user, internalObjectId, ABSTRACT_INTERNAL_OBJECT).then((internalObject) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].CONTEXT_TOPIC, internalObject, user);
  });
};
