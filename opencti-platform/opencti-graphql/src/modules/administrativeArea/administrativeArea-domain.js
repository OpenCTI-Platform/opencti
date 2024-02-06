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
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from './administrativeArea-types';
export const findById = (context, user, administrativeAreaId) => {
    return storeLoadById(context, user, administrativeAreaId, ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA], opts);
};
export const addAdministrativeArea = (context, user, administrativeArea) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, Object.assign(Object.assign({}, administrativeArea), { x_opencti_location_type: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA }), ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
