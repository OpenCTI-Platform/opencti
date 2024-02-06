var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { createEntity, loadEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { FilterMode } from '../../generated/graphql';
import { SYSTEM_USER } from '../../utils/access';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { defaultEntitySetting, getAvailableSettings } from './entitySetting-utils';
import { queryDefaultSubTypes } from '../../domain/subType';
import { publishUserAction } from '../../listener/UserActionListener';
import { telemetry } from '../../config/tracing';
import { INPUT_AUTHORIZED_MEMBERS } from '../../schema/general';
import { containsValidAdmin } from '../../utils/authorizedMembers';
import { FunctionalError } from '../../config/errors';
import { getEntitySettingSchemaAttributes, getMandatoryAttributesForSetting } from './entitySetting-attributeUtils';
// -- LOADING --
export const findById = (context, user, entitySettingId) => __awaiter(void 0, void 0, void 0, function* () {
    return storeLoadById(context, user, entitySettingId, ENTITY_TYPE_ENTITY_SETTING);
});
export const findByType = (context, user, targetType) => __awaiter(void 0, void 0, void 0, function* () {
    const findByTypeFn = () => __awaiter(void 0, void 0, void 0, function* () {
        return loadEntity(context, user, [ENTITY_TYPE_ENTITY_SETTING], {
            filters: {
                mode: 'and',
                filters: [{ key: 'target_type', values: [targetType] }],
                filterGroups: [],
            }
        });
    });
    return telemetry(context, user, 'QUERY entitySetting', {
        [SemanticAttributes.DB_NAME]: 'entitySetting_domain',
        [SemanticAttributes.DB_OPERATION]: 'read',
    }, findByTypeFn);
});
export const batchEntitySettingsByType = (context, user, targetTypes) => __awaiter(void 0, void 0, void 0, function* () {
    const findByTypeFn = () => __awaiter(void 0, void 0, void 0, function* () {
        const entitySettings = yield listAllEntities(context, user, [ENTITY_TYPE_ENTITY_SETTING], {
            filters: {
                mode: FilterMode.And,
                filters: [{ key: ['target_type'], values: targetTypes }],
                filterGroups: [],
            },
            connectionFormat: false
        });
        return targetTypes.map((targetType) => entitySettings.find((entitySetting) => entitySetting.target_type === targetType));
    });
    return telemetry(context, user, 'BATCH entitySettings', {
        [SemanticAttributes.DB_NAME]: 'entitySetting_domain',
        [SemanticAttributes.DB_OPERATION]: 'read',
    }, findByTypeFn);
});
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_ENTITY_SETTING], opts);
};
export const entitySettingEditField = (context, user, entitySettingId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const authorizedMembersEdit = input
        .filter(({ key, value }) => key === 'attributes_configuration' && value.length > 0)
        .flatMap(({ value }) => JSON.parse(value[0]))
        .find(({ name }) => name === INPUT_AUTHORIZED_MEMBERS);
    if (authorizedMembersEdit && Array.isArray(authorizedMembersEdit.default_values)) {
        const hasValidAdmin = yield containsValidAdmin(context, authorizedMembersEdit.default_values.map(JSON.parse), ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS']);
        if (!hasValidAdmin) {
            throw FunctionalError('It should have at least one member with admin access');
        }
    }
    const { element } = yield updateAttribute(context, user, entitySettingId, ENTITY_TYPE_ENTITY_SETTING, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for entity setting \`${element.target_type}\``,
        context_data: { id: entitySettingId, entity_type: element.target_type, input }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].EDIT_TOPIC, element, user);
});
export const entitySettingsEditField = (context, user, entitySettingIds, input) => __awaiter(void 0, void 0, void 0, function* () {
    return Promise.all(entitySettingIds.map((entitySettingId) => entitySettingEditField(context, user, entitySettingId, input)));
});
// -- INITIALIZATION --
export const addEntitySetting = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, entitySetting, ENTITY_TYPE_ENTITY_SETTING);
    yield notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].ADDED_TOPIC, created, user);
});
export const initCreateEntitySettings = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    // First check existing
    const subTypes = yield queryDefaultSubTypes(context, user);
    // Get all current settings
    const entitySettings = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
    const currentEntityTypes = entitySettings.map((e) => e.target_type);
    for (let index = 0; index < subTypes.edges.length; index += 1) {
        const entityType = subTypes.edges[index].node.id;
        // If setting not yet initialize, do it
        if (!currentEntityTypes.includes(entityType)) {
            const availableSettings = getAvailableSettings(entityType);
            const entitySetting = {
                target_type: entityType
            };
            availableSettings.forEach((key) => {
                if (defaultEntitySetting[key] !== undefined) {
                    entitySetting[key] = defaultEntitySetting[key];
                }
            });
            yield addEntitySetting(context, SYSTEM_USER, entitySetting);
        }
    }
});
// -- Schema
// Fetch the schemas attributes for an entity setting and extend them with
// what is saved in this entity setting.
export const queryEntitySettingSchemaAttributes = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    return getEntitySettingSchemaAttributes(context, user, entitySetting);
});
export const queryScaleAttributesForSetting = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const attributes = yield getEntitySettingSchemaAttributes(context, user, entitySetting);
    return attributes.filter((a) => a.scale).map((a) => { var _a; return ({ name: a.name, scale: (_a = a.scale) !== null && _a !== void 0 ? _a : '' }); });
});
export const queryMandatoryAttributesForSetting = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    return getMandatoryAttributesForSetting(context, user, entitySetting);
});
export const queryDefaultValuesAttributesForSetting = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const attributes = yield getEntitySettingSchemaAttributes(context, user, entitySetting);
    return attributes.filter((a) => a.defaultValues).map((a) => { var _a; return (Object.assign(Object.assign({}, a), { defaultValues: (_a = a.defaultValues) !== null && _a !== void 0 ? _a : [] })); });
});
