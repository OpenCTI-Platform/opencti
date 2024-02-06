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
import { listAllEntities, storeLoadById } from '../../database/middleware-loader';
import { createEntity, loadEntity, patchAttribute, updateAttribute } from '../../database/middleware';
import { getEntitiesListFromCache } from '../../database/cache';
import { telemetry } from '../../config/tracing';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from './managerConfiguration-types';
import { getAllDefaultManagerConfigurations, getDefaultManagerConfiguration } from './managerConfiguration-utils';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
export const findById = (context, user, id) => __awaiter(void 0, void 0, void 0, function* () {
    return storeLoadById(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION);
});
export const findByManagerId = (context, user, managerId) => __awaiter(void 0, void 0, void 0, function* () {
    const findByTypeFn = () => __awaiter(void 0, void 0, void 0, function* () {
        return loadEntity(context, user, [ENTITY_TYPE_MANAGER_CONFIGURATION], {
            filters: {
                mode: 'and',
                filters: [
                    { key: ['manager_id'], values: [managerId], mode: 'or', operator: 'eq' }
                ],
                filterGroups: [],
            }
        });
    });
    return telemetry(context, user, 'QUERY managerConfiguration', {
        [SemanticAttributes.DB_NAME]: 'managerConfiguration_domain',
        [SemanticAttributes.DB_OPERATION]: 'read',
    }, findByTypeFn);
});
export const managerConfigurationEditField = (context, user, id, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element } = yield updateAttribute(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for manager configuration \`${element.manager_id}\``,
        context_data: { id, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, element, user);
});
export const managerConfigurationResetSetting = (context, user, id) => __awaiter(void 0, void 0, void 0, function* () {
    const managerConfiguration = yield findById(context, user, id);
    const patch = { manager_setting: getDefaultManagerConfiguration(managerConfiguration.manager_id) };
    const updatedManagerConfiguration = yield patchAttribute(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION, patch);
    yield notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, updatedManagerConfiguration, user);
});
export const getManagerConfigurationFromCache = (context, user, managerId) => __awaiter(void 0, void 0, void 0, function* () {
    const managerConfigurations = yield getEntitiesListFromCache(context, user, ENTITY_TYPE_MANAGER_CONFIGURATION);
    return managerConfigurations.find((m) => m.manager_id === managerId);
});
export const updateManagerConfigurationLastRun = (context, user, managerConfigurationId, updateInput) => __awaiter(void 0, void 0, void 0, function* () {
    const updatedManagerConfiguration = yield patchAttribute(context, user, managerConfigurationId, ENTITY_TYPE_MANAGER_CONFIGURATION, updateInput);
    yield notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, updatedManagerConfiguration, user);
});
// -- INITIALIZATION --
const addManagerConfiguration = (context, user, managerConfiguration) => __awaiter(void 0, void 0, void 0, function* () {
    const createdManagerConfiguration = yield createEntity(context, user, managerConfiguration, ENTITY_TYPE_MANAGER_CONFIGURATION);
    yield notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].ADDED_TOPIC, createdManagerConfiguration, user);
});
export const initManagerConfigurations = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const managerConfigurations = yield listAllEntities(context, user, [ENTITY_TYPE_MANAGER_CONFIGURATION], { connectionFormat: false });
    const allManagerConfigurations = getAllDefaultManagerConfigurations();
    for (let index = 0; index < allManagerConfigurations.length; index += 1) {
        const managerConfiguration = Object.assign({}, allManagerConfigurations[index]);
        const managerConfigurationExist = managerConfigurations.some((m) => m.manager_id === managerConfiguration.manager_id);
        if (!managerConfigurationExist) {
            yield addManagerConfiguration(context, user, managerConfiguration);
        }
    }
});
