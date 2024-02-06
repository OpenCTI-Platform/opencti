var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
const listeners = new Map();
export const registerUserActionListener = (listener) => {
    listeners.set(listener.id, listener);
    return { unregister: () => listeners.delete(listener.id) };
};
export const publishUserAction = (userAction) => __awaiter(void 0, void 0, void 0, function* () {
    const actionPromises = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const [, listener] of listeners.entries()) {
        actionPromises.push(listener.next(userAction));
    }
    return Promise.all(actionPromises);
});
export const buildContextDataForFile = (entity, path, filename) => {
    var _a;
    const contextData = {
        path,
        id: entity === null || entity === void 0 ? void 0 : entity.internal_id,
        entity_name: entity ? extractEntityRepresentativeName(entity) : 'global',
        entity_type: (_a = entity === null || entity === void 0 ? void 0 : entity.entity_type) !== null && _a !== void 0 ? _a : 'global',
        file_name: filename,
    };
    if (entity) {
        if (entity.creator_id) {
            contextData.creator_ids = Array.isArray(entity.creator_id) ? entity.creator_id : [entity.creator_id];
        }
        if (entity[RELATION_GRANTED_TO]) {
            contextData.granted_refs_ids = entity[RELATION_GRANTED_TO];
        }
        if (entity[RELATION_OBJECT_MARKING]) {
            contextData.object_marking_refs_ids = entity[RELATION_OBJECT_MARKING];
        }
        if (entity[RELATION_CREATED_BY]) {
            contextData.created_by_ref_id = entity[RELATION_CREATED_BY];
        }
        if (entity[RELATION_OBJECT_LABEL]) {
            contextData.labels_ids = entity[RELATION_OBJECT_LABEL];
        }
    }
    return contextData;
};
