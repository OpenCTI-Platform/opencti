var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_NARRATIVE } from './narrative-types';
import { RELATION_SUBNARRATIVE_OF } from '../../schema/stixCoreRelationship';
export const findById = (context, user, narrativeId) => {
    return storeLoadById(context, user, narrativeId, ENTITY_TYPE_NARRATIVE);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_NARRATIVE], opts);
};
export const addNarrative = (context, user, narrative) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, narrative, ENTITY_TYPE_NARRATIVE);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const parentNarrativesPaginated = (context, user, narrativeId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, narrativeId, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE, false, args);
});
export const childNarrativesPaginated = (context, user, narrativeId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, narrativeId, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE, true, args);
});
export const isSubNarrative = (context, user, narrativeId) => __awaiter(void 0, void 0, void 0, function* () {
    const pagination = yield parentNarrativesPaginated(context, user, narrativeId, { first: 1 });
    return pagination.edges.length > 0;
});
