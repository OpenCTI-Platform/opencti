var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import Ajv from 'ajv';
import { BUS_TOPICS } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { internalFindByIds, listAllEntities, listEntitiesPaginated, storeLoadById, } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { isEmptyField } from '../../database/utils';
import { publishUserAction } from '../../listener/UserActionListener';
import { internalProcessNotification } from '../../manager/publisherManager';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { MOCK_NOTIFICATIONS } from '../../utils/publisher-mock';
import { BUILTIN_NOTIFIERS_CONNECTORS, DEFAULT_TEAM_DIGEST_MESSAGE, DEFAULT_TEAM_MESSAGE, NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_UI, STATIC_NOTIFIERS } from './notifier-statics';
import { ENTITY_TYPE_NOTIFIER } from './notifier-types';
const ajv = new Ajv();
const validateNotifier = (notifier) => {
    var _a;
    const notifierConnector = BUILTIN_NOTIFIERS_CONNECTORS[notifier.notifier_connector_id];
    if (isEmptyField(notifierConnector) || isEmptyField(notifierConnector.connector_schema)) {
        throw UnsupportedError('Invalid notifier connector', { id: notifier.notifier_connector_id });
    }
    // Connector Schema is valued, we have checked that before
    const validate = ajv.compile(JSON.parse((_a = notifierConnector.connector_schema) !== null && _a !== void 0 ? _a : '{}'));
    const isValidConfiguration = validate(JSON.parse(notifier.notifier_configuration));
    if (!isValidConfiguration) {
        throw UnsupportedError('This configuration is invalid', { configuration: notifier.notifier_configuration });
    }
};
export const addNotifier = (context, user, notifier) => __awaiter(void 0, void 0, void 0, function* () {
    validateNotifier(notifier);
    const notifierToCreate = Object.assign(Object.assign({}, notifier), { created: now(), updated: now(), authorized_authorities: ['SETTINGS'] });
    const created = yield createEntity(context, user, notifierToCreate, ENTITY_TYPE_NOTIFIER);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'administration',
        message: `creates notifier \`${created.name}\` for connector  \`${created.notifier_connector_id}\``,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_NOTIFIER, input: created }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].ADDED_TOPIC, created, user);
});
export const notifierGet = (context, user, notifierId) => {
    return storeLoadById(context, user, notifierId, ENTITY_TYPE_NOTIFIER);
};
export const notifierEdit = (context, user, notifierId, input) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    const fieldsToValidate = {
        notifier_configuration: (_a = input.filter((n) => n.key === 'notifier_configuration')[0].value[0]) !== null && _a !== void 0 ? _a : '',
        notifier_connector_id: (_b = input.filter((n) => n.key === 'notifier_connector_id')[0].value[0]) !== null && _b !== void 0 ? _b : '',
    };
    validateNotifier(fieldsToValidate);
    const finalInput = input.map(({ key, value }) => {
        const item = { key, value };
        if (key === 'authorized_members') {
            item.value = value.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
        }
        return item;
    });
    const { element: updatedElem } = yield updateAttribute(context, user, notifierId, ENTITY_TYPE_NOTIFIER, finalInput);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for synchronizer \`${updatedElem.name}\``,
        context_data: { id: notifierId, entity_type: ENTITY_TYPE_SYNC, input }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].EDIT_TOPIC, updatedElem, user);
});
export const notifierDelete = (context, user, triggerId) => __awaiter(void 0, void 0, void 0, function* () {
    const element = yield deleteElementById(context, user, triggerId, ENTITY_TYPE_NOTIFIER);
    yield notify(BUS_TOPICS[ENTITY_TYPE_NOTIFIER].DELETE_TOPIC, element, user);
    return triggerId;
});
export const notifiersFind = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_NOTIFIER], Object.assign(Object.assign({}, opts), { includeAuthorities: true }));
};
export const getNotifiers = (context, user, ids) => __awaiter(void 0, void 0, void 0, function* () {
    const notifiers = yield internalFindByIds(context, user, ids, { type: ENTITY_TYPE_NOTIFIER });
    const staticNotifiers = STATIC_NOTIFIERS.filter(({ id }) => ids.includes(id));
    return [...notifiers, ...staticNotifiers];
});
export const usableNotifiers = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const notifiers = yield listAllEntities(context, user, [ENTITY_TYPE_NOTIFIER], { includeAuthorities: true });
    return [...notifiers, ...STATIC_NOTIFIERS].sort((a, b) => {
        if (a.name < b.name)
            return -1;
        if (a.name > b.name)
            return 1;
        return 0;
    });
});
export const getNotifierConnector = (context, user, connectorId) => {
    const builtIn = BUILTIN_NOTIFIERS_CONNECTORS[connectorId];
    if (builtIn) {
        return builtIn;
    }
    if ([NOTIFIER_CONNECTOR_UI, NOTIFIER_CONNECTOR_EMAIL].includes(connectorId)) {
        return { id: connectorId, name: 'Platform' };
    }
    return storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
};
export const initDefaultNotifiers = (context) => {
    return Promise.all([DEFAULT_TEAM_MESSAGE, DEFAULT_TEAM_DIGEST_MESSAGE].map((notifier) => addNotifier(context, SYSTEM_USER, notifier)));
};
export const testNotifier = (context, user, notifier) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        validateNotifier(notifier);
    }
    catch (error) {
        return error.data.reason;
    }
    const settings = yield getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const notificationMap = new Map([
        ['default_notification_id', { name: 'test' }],
        ['default_notification_id_2', { name: 'test 2' }],
        ['default_activity_id', { name: 'test 2' }],
    ]);
    const result = yield internalProcessNotification(context, settings, notificationMap, {
        user_id: user.id,
        user_email: user.user_email,
        notifiers: [],
    }, notifier, MOCK_NOTIFICATIONS[notifier.notifier_test_id], { created: (new Date()).toISOString() });
    return result === null || result === void 0 ? void 0 : result.error;
});
