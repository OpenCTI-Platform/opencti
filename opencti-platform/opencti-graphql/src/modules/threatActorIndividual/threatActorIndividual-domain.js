var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { assoc, isNil, pipe } from 'ramda';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey, } from '../../schema/general';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import { FROM_START, UNTIL_END } from '../../utils/format';
import { FilterMode } from '../../generated/graphql';
export const findById = (context, user, threatActorIndividualId) => {
    return storeLoadById(context, user, threatActorIndividualId, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
};
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL], opts);
};
export const addThreatActorIndividual = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const threatActor = pipe(assoc('first_seen', isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen), assoc('last_seen', isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen))(input);
    const created = yield createEntity(context, user, threatActor, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const threatActorIndividualContainsStixObjectOrStixRelationship = (context, user, threatActorIndividualId, thingId) => __awaiter(void 0, void 0, void 0, function* () {
    const resolvedThingId = isStixId(thingId) ? (yield internalLoadById(context, user, thingId)).internal_id : thingId;
    const args = {
        filters: {
            mode: FilterMode.And,
            filterGroups: [],
            filters: [
                {
                    key: ['internal_id'],
                    values: [threatActorIndividualId],
                },
                {
                    key: [buildRefRelationKey(RELATION_OBJECT)],
                    values: [resolvedThingId],
                }
            ],
        },
    };
    const threatActorIndividualFound = yield findAll(context, user, args);
    return threatActorIndividualFound.edges.length > 0;
});
