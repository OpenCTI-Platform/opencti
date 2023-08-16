import { BUS_TOPICS } from '../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { EntityOptions, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindById } from '../../domain/domainTypes';

import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, TaskAddInput } from '../../generated/graphql';
import { now } from '../../utils/format';
import type { BasicStoreEntityPlaybook } from './playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { PLAYBOOK_COMPONENTS } from './playbook-components';

export const findById: DomainFindById<BasicStoreEntityPlaybook> = (context: AuthContext, user: AuthUser, playbookId: string) => {
  return storeLoadById(context, user, playbookId, ENTITY_TYPE_PLAYBOOK);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPlaybook>) => {
  return listEntitiesPaginated<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK], opts);
};

export const findAllPlaybooks = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPlaybook>) => {
  return listAllEntities<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK], opts);
};

export const availableComponents = () => {
  return Object.values(PLAYBOOK_COMPONENTS);
};

export const playbookAdd = async (context: AuthContext, user: AuthUser, input: TaskAddInput) => {
  const playbookToCreate = input.created ? input : { ...input, created: now() };
  const created = await createEntity(context, user, playbookToCreate, ENTITY_TYPE_PLAYBOOK);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const playbookDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(context, user, id, ENTITY_TYPE_PLAYBOOK);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
  return id;
};

export const playbookEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
};
