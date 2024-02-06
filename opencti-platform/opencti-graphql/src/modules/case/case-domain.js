var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { BUS_TOPICS } from '../../config/conf';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_CASE, } from './case-types';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../task/task-template/task-template-types';
import { TEMPLATE_TASK_RELATION } from './case-template/case-template-types';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { taskAdd } from '../task/task-domain';
import { FilterMode } from '../../generated/graphql';
export const findById = (context, user, caseId) => {
    return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};
export const upsertTemplateForCase = (context, user, id, caseTemplateId) => __awaiter(void 0, void 0, void 0, function* () {
    const currentCase = yield findById(context, user, id);
    // Get all tasks from template
    const opts = {
        filters: {
            mode: FilterMode.And,
            filters: [{ key: [buildRefRelationKey(TEMPLATE_TASK_RELATION)], values: [caseTemplateId] }],
            filterGroups: [],
        }
    };
    const templateTasks = yield listAllEntities(context, user, [ENTITY_TYPE_TASK_TEMPLATE], opts);
    // Convert template to real task
    const tasks = templateTasks.map((template) => {
        return { name: template.name, description: template.description, objects: [id], objectMarking: currentCase[RELATION_OBJECT_MARKING] };
    });
    // Create all tasks
    for (let index = 0; index < tasks.length; index += 1) {
        const task = tasks[index];
        yield taskAdd(context, user, {
            name: task.name,
            description: task.description,
            objects: [id],
            objectMarking: currentCase[RELATION_OBJECT_MARKING],
        });
    }
    // Admin log
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, currentCase, user);
});
