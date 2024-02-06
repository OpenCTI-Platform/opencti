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
import { listEntitiesPaginated, listEntitiesThroughRelationsPaginated, loadEntityThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { RELATION_DATA_SOURCE } from './dataComponent-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { RELATION_DETECTS } from '../../schema/stixCoreRelationship';
export const findById = (context, user, dataComponentId) => {
    return storeLoadById(context, user, dataComponentId, ENTITY_TYPE_DATA_COMPONENT);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_DATA_COMPONENT], opts);
};
export const dataComponentAdd = (context, user, dataComponent) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, dataComponent, ENTITY_TYPE_DATA_COMPONENT);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const withDataSource = (context, user, dataComponentId) => __awaiter(void 0, void 0, void 0, function* () {
    return loadEntityThroughRelationsPaginated(context, user, dataComponentId, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_SOURCE, false);
});
export const attackPatternsPaginated = (context, user, dataComponentId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, dataComponentId, RELATION_DETECTS, ENTITY_TYPE_ATTACK_PATTERN, false, args);
});
