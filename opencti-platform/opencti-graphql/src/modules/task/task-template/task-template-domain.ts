import { BUS_TOPICS } from '../../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import type { DomainFindById } from '../../../domain/domainTypes';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import type { AuthContext, AuthUser } from '../../../types/user';
import { type BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE, type StoreEntityTaskTemplate } from './task-template-types';
import { publishUserAction } from '../../../listener/UserActionListener';
import type { EditInput, TaskTemplateAddInput } from '../../../generated/graphql';

export const findById: DomainFindById<BasicStoreEntityTaskTemplate> = (context: AuthContext, user: AuthUser, templateId: string) => {
  return storeLoadById(context, user, templateId, ENTITY_TYPE_TASK_TEMPLATE);
};

export const findTaskTemplatePaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityTaskTemplate>) => {
  return pageEntitiesConnection<BasicStoreEntityTaskTemplate>(context, user, [ENTITY_TYPE_TASK_TEMPLATE], opts);
};

export const taskTemplateAdd = async (context: AuthContext, user: AuthUser, input: TaskTemplateAddInput) => {
  const created = await createEntity(context, user, input, ENTITY_TYPE_TASK_TEMPLATE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Task \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const taskTemplateDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById<StoreEntityTaskTemplate>(context, user, id, ENTITY_TYPE_TASK_TEMPLATE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Task \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input: element },
  });
  return id;
};

export const taskTemplateEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute<StoreEntityTaskTemplate>(context, user, id, ENTITY_TYPE_TASK_TEMPLATE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for Task \`${updatedElem.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
};
