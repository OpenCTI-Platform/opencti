import { Promise as BluePromise } from 'bluebird';
import { BUS_TOPICS } from '../../config/conf';
import type { EntityOptions } from '../../database/middleware-loader';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { containersObjectsOfObject } from '../../domain/container';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import { caseTaskAdd } from './case-task/case-task-domain';
import { ENTITY_TYPE_CONTAINER_CASE_TASK } from './case-task/case-task-types';
import { BasicStoreEntityCase, ENTITY_TYPE_CONTAINER_CASE, } from './case-types';

export const findById = (context: AuthContext, user: AuthUser, caseId: string): BasicStoreEntityCase => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE) as unknown as BasicStoreEntityCase;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};

export const upsertTemplateForCase = async (context: AuthContext, user: AuthUser, id: string, caseTemplateId: string) => {
  const currentCase = await findById(context, user, id);
  const tasks = await containersObjectsOfObject(context, context.user, { id: caseTemplateId, types: [ENTITY_TYPE_CONTAINER_CASE_TASK] });
  await BluePromise.map(tasks.edges, async ({ node: task }) => {
    await caseTaskAdd(context, user, {
      name: task.name,
      description: task.description,
      useAsTemplate: false,
      objects: [id],
      objectMarking: currentCase[RELATION_OBJECT_MARKING],
    });
  });
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, currentCase, user);
};
