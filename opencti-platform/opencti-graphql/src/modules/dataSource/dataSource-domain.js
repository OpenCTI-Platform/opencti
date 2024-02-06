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
import { listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { INPUT_DATA_SOURCE, RELATION_DATA_SOURCE } from '../dataComponent/dataComponent-types';
export const findById = (context, user, dataSourceId) => {
    return storeLoadById(context, user, dataSourceId, ENTITY_TYPE_DATA_SOURCE);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_DATA_SOURCE], opts);
};
export const dataSourceAdd = (context, user, dataSource) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, dataSource, ENTITY_TYPE_DATA_SOURCE);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const dataComponentsPaginated = (context, user, dataSourceId, opts) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, dataSourceId, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_COMPONENT, true, opts);
});
export const dataSourceDataComponentAdd = (context, user, dataSourceId, dataComponentId) => __awaiter(void 0, void 0, void 0, function* () {
    yield stixDomainObjectEditField(context, user, dataComponentId, { key: INPUT_DATA_SOURCE, value: [dataSourceId] });
    return findById(context, user, dataSourceId);
});
export const dataSourceDataComponentDelete = (context, user, dataSourceId, dataComponentId) => __awaiter(void 0, void 0, void 0, function* () {
    yield stixDomainObjectEditField(context, user, dataComponentId, { key: INPUT_DATA_SOURCE, value: [null] });
    return findById(context, user, dataSourceId);
});
