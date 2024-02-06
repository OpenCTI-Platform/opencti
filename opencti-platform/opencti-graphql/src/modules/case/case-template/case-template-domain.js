var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_CASE_TEMPLATE, TEMPLATE_TASK_RELATION } from './case-template-types';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { notify } from '../../../database/redis';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { publishUserAction } from '../../../listener/UserActionListener';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../../domain/stixObjectOrStixRelationship';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../../task/task-template/task-template-types';
export const findById = (context, user, templateId) => {
    return storeLoadById(context, user, templateId, ENTITY_TYPE_CASE_TEMPLATE);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CASE_TEMPLATE], opts);
};
export const taskTemplatesPaginated = (context, user, caseId, opts) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, caseId, TEMPLATE_TASK_RELATION, ENTITY_TYPE_TASK_TEMPLATE, false, opts);
});
export const caseTemplateAdd = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, input, ENTITY_TYPE_CASE_TEMPLATE);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'administration',
        message: `creates case template \`${input.name}\``,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
});
export const caseTemplateDelete = (context, user, caseTemplateId) => __awaiter(void 0, void 0, void 0, function* () {
    const element = yield deleteElementById(context, user, caseTemplateId, ENTITY_TYPE_CASE_TEMPLATE);
    yield notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `deletes case template \`${element.name}\``,
        context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input: element }
    });
    return caseTemplateId;
});
export const caseTemplateEdit = (context, user, caseTemplateId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element: updatedElem } = yield updateAttribute(context, user, caseTemplateId, ENTITY_TYPE_CASE_TEMPLATE, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for case template \`${updatedElem.name}\``,
        context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
});
export const caseTemplateAddRelation = (context, user, caseTemplateId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const relation = yield stixObjectOrRelationshipAddRefRelation(context, user, caseTemplateId, input, ABSTRACT_INTERNAL_OBJECT);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `adds Task template \`${extractEntityRepresentativeName(relation.from)}\` for case template \`${relation.to.name}\``,
        context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input }
    });
    return relation.to;
});
export const caseTemplateDeleteRelation = (context, user, caseTemplateId, toId, relationshipType) => __awaiter(void 0, void 0, void 0, function* () {
    const relation = yield stixObjectOrRelationshipDeleteRefRelation(context, user, caseTemplateId, toId, relationshipType, ABSTRACT_INTERNAL_OBJECT);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `removes Task template \`${extractEntityRepresentativeName(relation.from)}\` for case template \`${relation.to.name}\``,
        context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input: { caseTemplateId, toId, relationshipType } }
    });
    return relation.to;
});
