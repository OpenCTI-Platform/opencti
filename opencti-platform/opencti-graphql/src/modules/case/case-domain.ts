import { BUS_TOPICS } from '../../config/conf';
import type { EntityOptions } from '../../database/middleware-loader';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import { BasicStoreEntityCase, ENTITY_TYPE_CONTAINER_CASE, } from './case-types';
import { BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE } from '../task/task-template/task-template-types';
import { TEMPLATE_TASK_RELATION } from './case-template/case-template-types';
import { RELATION_OBJECT_MARKING, RELATION_OBJECT_PARTICIPANT } from '../../schema/stixRefRelationship';
import { taskAdd } from '../task/task-domain';
import { batchListThroughGetTo } from '../../database/middleware';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

export const findById = (context: AuthContext, user: AuthUser, caseId: string): BasicStoreEntityCase => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE) as unknown as BasicStoreEntityCase;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};

export const batchParticipants = (context: AuthContext, user: AuthUser, caseIds: string[]) => {
  return batchListThroughGetTo(context, user, caseIds, RELATION_OBJECT_PARTICIPANT, ENTITY_TYPE_USER);
};

export const upsertTemplateForCase = async (context: AuthContext, user: AuthUser, id: string, caseTemplateId: string) => {
  const currentCase = await findById(context, user, id);
  // Get all tasks from template
  const opts = { filters: [{ key: buildRefRelationKey(TEMPLATE_TASK_RELATION), values: [caseTemplateId] }] };
  const templateTasks = await listAllEntities<BasicStoreEntityTaskTemplate>(context, user, [ENTITY_TYPE_TASK_TEMPLATE], opts);
  // Convert template to real task
  const tasks = templateTasks.map((template) => {
    return { name: template.name, description: template.description, objects: [id], objectMarking: currentCase[RELATION_OBJECT_MARKING] };
  });
  // Create all tasks
  for (let index = 0; index < tasks.length; index += 1) {
    const task = tasks[index];
    await taskAdd(context, user, {
      name: task.name,
      description: task.description,
      objects: [id],
      objectMarking: currentCase[RELATION_OBJECT_MARKING],
    });
  }
  // Admin log
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, currentCase, user);
};
