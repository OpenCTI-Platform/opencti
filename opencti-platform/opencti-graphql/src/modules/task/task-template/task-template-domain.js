var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { BUS_TOPICS } from '../../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { ENTITY_TYPE_TASK_TEMPLATE } from './task-template-types';
import { publishUserAction } from '../../../listener/UserActionListener';
export const findById = (context, user, templateId) => {
    return storeLoadById(context, user, templateId, ENTITY_TYPE_TASK_TEMPLATE);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_TASK_TEMPLATE], opts);
};
export const taskTemplateAdd = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, input, ENTITY_TYPE_TASK_TEMPLATE);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'administration',
        message: `creates Task \`${input.name}\``,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const taskTemplateDelete = (context, user, id) => __awaiter(void 0, void 0, void 0, function* () {
    const element = yield deleteElementById(context, user, id, ENTITY_TYPE_TASK_TEMPLATE);
    yield notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `deletes Task \`${element.name}\``,
        context_data: { id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input: element }
    });
    return id;
});
export const taskTemplateEdit = (context, user, id, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element: updatedElem } = yield updateAttribute(context, user, id, ENTITY_TYPE_TASK_TEMPLATE, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for Task \`${updatedElem.name}\``,
        context_data: { id, entity_type: ENTITY_TYPE_TASK_TEMPLATE, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
});
