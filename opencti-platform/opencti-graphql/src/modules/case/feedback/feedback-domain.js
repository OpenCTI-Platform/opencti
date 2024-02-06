var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity, patchAttribute } from '../../../database/middleware';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';
import { isValidMemberAccessRight } from '../../../utils/access';
import { containsValidAdmin } from '../../../utils/authorizedMembers';
import { FunctionalError } from '../../../config/errors';
export const findById = (context, user, caseId) => {
    return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_FEEDBACK);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_FEEDBACK], opts);
};
export const addFeedback = (context, user, feedbackAdd) => __awaiter(void 0, void 0, void 0, function* () {
    let caseToCreate = feedbackAdd.created ? feedbackAdd : Object.assign(Object.assign({}, feedbackAdd), { created: now() });
    if (isEmptyField(feedbackAdd.createdBy)) {
        let individualId = user.individual_id;
        if (individualId === undefined) {
            const individual = yield userAddIndividual(context, user);
            individualId = individual.id;
        }
        caseToCreate = Object.assign(Object.assign({}, caseToCreate), { createdBy: individualId });
    }
    const created = yield createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_FEEDBACK);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const feedbackContainsStixObjectOrStixRelationship = (context, user, feedbackId, thingId) => __awaiter(void 0, void 0, void 0, function* () {
    const resolvedThingId = isStixId(thingId) ? (yield internalLoadById(context, user, thingId)).internal_id : thingId;
    const args = {
        filters: {
            mode: FilterMode.And,
            filters: [
                { key: ['internal_id'], values: [feedbackId] },
                { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
            ],
            filterGroups: [],
        },
    };
    const feedbackFound = yield findAll(context, user, args);
    return feedbackFound.edges.length > 0;
});
export const feedbackEditAuthorizedMembers = (context, user, entityId, input) => __awaiter(void 0, void 0, void 0, function* () {
    let authorized_members = null;
    if (input) {
        // validate input (validate access right) and remove duplicates
        const filteredInput = input.filter((value, index, array) => {
            return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id) === index;
        });
        const hasValidAdmin = yield containsValidAdmin(context, filteredInput, ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS']);
        if (!hasValidAdmin) {
            throw FunctionalError('It should have at least one valid member with admin access');
        }
        authorized_members = filteredInput.map(({ id, access_right }) => ({ id, access_right }));
    }
    const patch = { authorized_members };
    const { element } = yield patchAttribute(context, user, entityId, ENTITY_TYPE_CONTAINER_FEEDBACK, patch);
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, element, user);
});
