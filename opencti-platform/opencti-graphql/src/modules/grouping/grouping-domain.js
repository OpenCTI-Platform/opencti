var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as R from 'ramda';
import { createEntity, distributionEntities, timeSeriesEntities } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import { FilterMode } from '../../generated/graphql';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_GROUPING } from './grouping-types';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { elCount } from '../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
export const findById = (context, user, groupingId) => {
    return storeLoadById(context, user, groupingId, ENTITY_TYPE_CONTAINER_GROUPING);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], opts);
};
export const addGrouping = (context, user, grouping) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, grouping, ENTITY_TYPE_CONTAINER_GROUPING);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
// Entities tab
export const groupingContainsStixObjectOrStixRelationship = (context, user, groupingId, thingId) => __awaiter(void 0, void 0, void 0, function* () {
    const resolvedThingId = isStixId(thingId) ? (yield internalLoadById(context, user, thingId)).internal_id : thingId;
    const opts = {
        filters: {
            mode: FilterMode.And,
            filters: [
                { key: ['internal_id'], values: [groupingId] },
                { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
            ],
            filterGroups: [],
        },
    };
    const groupingFound = yield findAll(context, user, opts);
    return groupingFound.edges.length > 0;
});
// region series
export const groupingsTimeSeries = (context, user, args) => {
    return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], args);
};
export const groupingsNumber = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, args), { types: [ENTITY_TYPE_CONTAINER_GROUPING] }));
    const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, R.dissoc('endDate', args)), { types: [ENTITY_TYPE_CONTAINER_GROUPING] }));
    const [count, total] = yield Promise.all([countPromise, totalPromise]);
    return { count, total };
});
export const groupingsTimeSeriesByEntity = (context, user, args) => {
    const { objectId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
    return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], Object.assign(Object.assign({}, args), { filters }));
};
export const groupingsTimeSeriesByAuthor = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { authorId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
    return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], Object.assign(Object.assign({}, args), { filters }));
});
export const groupingsNumberByEntity = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { objectId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
    const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, args), { types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }));
    const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, R.dissoc('endDate', args)), { types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }));
    const [count, total] = yield Promise.all([countPromise, totalPromise]);
    return { count, total };
});
export const groupingsNumberByAuthor = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { authorId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
    const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, args), { types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }));
    const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, R.dissoc('endDate', args)), { types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }));
    const [count, total] = yield Promise.all([countPromise, totalPromise]);
    return { count, total };
});
export const groupingsDistributionByEntity = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { objectId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
    return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], Object.assign(Object.assign({}, args), { filters }));
});
// endregion
