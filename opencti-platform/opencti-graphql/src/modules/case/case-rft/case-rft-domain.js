var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity } from '../../../database/middleware';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { upsertTemplateForCase } from '../case-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from './case-rft-types';
import { FilterMode } from '../../../generated/graphql';
export const findById = (context, user, caseId) => {
    return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE_RFT);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_CASE_RFT], opts);
};
export const addCaseRft = (context, user, caseRftAdd) => __awaiter(void 0, void 0, void 0, function* () {
    let caseToCreate = caseRftAdd.created ? caseRftAdd : Object.assign(Object.assign({}, caseRftAdd), { created: now() });
    if (isEmptyField(caseRftAdd.createdBy)) {
        let individualId = user.individual_id;
        if (individualId === undefined) {
            const individual = yield userAddIndividual(context, user);
            individualId = individual.id;
        }
        caseToCreate = Object.assign(Object.assign({}, caseToCreate), { createdBy: individualId });
    }
    const { caseTemplates } = caseToCreate;
    delete caseToCreate.caseTemplates;
    const created = yield createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_RFT);
    if (caseTemplates) {
        yield Promise.all(caseTemplates.map((caseTemplate) => upsertTemplateForCase(context, user, created.id, caseTemplate)));
    }
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const caseRftContainsStixObjectOrStixRelationship = (context, user, caseRftId, thingId) => __awaiter(void 0, void 0, void 0, function* () {
    const resolvedThingId = isStixId(thingId) ? (yield internalLoadById(context, user, thingId)).internal_id : thingId;
    const args = {
        filters: {
            mode: FilterMode.And,
            filters: [
                { key: ['internal_id'], values: [caseRftId] },
                { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
            ],
            filterGroups: [],
        },
    };
    const caseRftFound = yield findAll(context, user, args);
    return caseRftFound.edges.length > 0;
});
