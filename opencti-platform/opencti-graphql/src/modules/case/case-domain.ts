import { BUS_TOPICS } from '../../config/conf';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityCase, ENTITY_TYPE_CONTAINER_CASE, } from './case-types';
import { type BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE } from '../task/task-template/task-template-types';
import { TEMPLATE_TASK_RELATION } from './case-template/case-template-types';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { taskAdd } from '../task/task-domain';
import { FilterMode } from '../../generated/graphql';

export const findById = async (context: AuthContext, user: AuthUser, caseId: string) => {
  return storeLoadById<BasicStoreEntityCase>(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE);
};

export const findAll = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};

export const upsertTemplateForCase = async (context: AuthContext, user: AuthUser, id: string, caseTemplateId: string) => {
  const currentCase = await findById(context, user, id);
  // Get all tasks from template
  const opts = {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: [buildRefRelationKey(TEMPLATE_TASK_RELATION)], values: [caseTemplateId] }],
      filterGroups: [],
    }
  };
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
