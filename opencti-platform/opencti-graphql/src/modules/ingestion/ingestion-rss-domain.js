var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { ENTITY_TYPE_INGESTION_RSS } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
export const findById = (context, user, ingestionId) => {
    return storeLoadById(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
};
export const findAllPaginated = (context, user, opts = {}) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
});
export const findAllRssIngestions = (context, user, opts = {}) => __awaiter(void 0, void 0, void 0, function* () {
    return listAllEntities(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
});
export const addIngestion = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element, isCreation } = yield createEntity(context, user, input, ENTITY_TYPE_INGESTION_RSS, { complete: true });
    if (isCreation) {
        yield publishUserAction({
            user,
            event_type: 'mutation',
            event_scope: 'create',
            event_access: 'administration',
            message: `creates rss ingestion \`${input.name}\``,
            context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_RSS, input }
        });
    }
    return element;
});
export const patchRssIngestion = (context, user, id, patch) => __awaiter(void 0, void 0, void 0, function* () {
    const patched = yield patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_RSS, patch);
    return patched.element;
});
export const ingestionEditField = (context, user, ingestionId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element } = yield updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for rss ingestion \`${element.name}\``,
        context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
});
export const ingestionDelete = (context, user, ingestionId) => __awaiter(void 0, void 0, void 0, function* () {
    const deleted = yield deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `deletes rss ingestion \`${deleted.name}\``,
        context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input: deleted }
    });
    return ingestionId;
});
