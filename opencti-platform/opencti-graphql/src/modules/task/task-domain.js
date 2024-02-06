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
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { internalLoadById, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_OBJECT, RELATION_OBJECT_PARTICIPANT } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_TASK } from './task-types';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../domain/stixObjectOrStixRelationship';
import { FilterMode } from '../../generated/graphql';
import { now } from '../../utils/format';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
export const findById = (context, user, templateId) => {
    return storeLoadById(context, user, templateId, ENTITY_TYPE_CONTAINER_TASK);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_TASK], opts);
};
export const caseTasksPaginated = (context, user, caseId, opts) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, caseId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_TASK, false, opts);
});
export const taskParticipantsPaginated = (context, user, caseId, opts) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, caseId, RELATION_OBJECT_PARTICIPANT, ENTITY_TYPE_USER, false, opts);
});
export const taskAdd = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const taskToCreate = input.created ? input : Object.assign(Object.assign({}, input), { created: now() });
    const created = yield createEntity(context, user, taskToCreate, ENTITY_TYPE_CONTAINER_TASK);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const taskDelete = (context, user, id) => __awaiter(void 0, void 0, void 0, function* () {
    const element = yield deleteElementById(context, user, id, ENTITY_TYPE_CONTAINER_TASK);
    yield notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
    return id;
});
export const taskEdit = (context, user, id, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element: updatedElem } = yield updateAttribute(context, user, id, ENTITY_TYPE_CONTAINER_TASK, input);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
});
export const taskContainsStixObjectOrStixRelationship = (context, user, taskId, thingId) => __awaiter(void 0, void 0, void 0, function* () {
    const resolvedThingId = isStixId(thingId) ? (yield internalLoadById(context, user, thingId)).internal_id : thingId;
    const args = {
        filters: {
            mode: FilterMode.And,
            filters: [
                { key: ['internal_id'], values: [taskId] },
                { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
            ],
            filterGroups: [],
        },
    };
    const taskFound = yield findAll(context, user, args);
    return taskFound.edges.length > 0;
});
export const taskAddRelation = (context, user, taskId, input) => __awaiter(void 0, void 0, void 0, function* () {
    return stixObjectOrRelationshipAddRefRelation(context, user, taskId, input, ABSTRACT_STIX_DOMAIN_OBJECT);
});
export const taskDeleteRelation = (context, user, taskId, toId, relationshipType) => __awaiter(void 0, void 0, void 0, function* () {
    return stixObjectOrRelationshipDeleteRefRelation(context, user, taskId, toId, relationshipType, ABSTRACT_STIX_DOMAIN_OBJECT);
});
