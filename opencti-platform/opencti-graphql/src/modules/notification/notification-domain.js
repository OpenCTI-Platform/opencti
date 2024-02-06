var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { TriggerType as TriggerTypeValue } from '../../generated/graphql';
import { internalFindByIds, internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TRIGGER, NOTIFICATION_NUMBER } from './notification-types';
import { now } from '../../utils/format';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { publishUserAction } from '../../listener/UserActionListener';
import { getUserAccessRight, isUserHasCapability, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_VIEW, VIRTUAL_ORGANIZATION_ADMIN, SETTINGS_SET_ACCESSES, SYSTEM_USER, } from '../../utils/access';
import { ForbiddenAccess, UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { validateFilterGroupForActivityEventMatch } from '../../utils/filtering/filtering-activity-event/activity-event-filtering';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
// Triggers
// Due to engine limitation we restrict the recipient to only one user for now
const extractUniqRecipient = (context, user, triggerInput, type) => __awaiter(void 0, void 0, void 0, function* () {
    const { recipients } = triggerInput;
    let recipient = user.id;
    if ((recipients === null || recipients === void 0 ? void 0 : recipients.length) && (recipients === null || recipients === void 0 ? void 0 : recipients.length) === 1) {
        if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && !isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
            throw ForbiddenAccess();
        }
        if ((recipients === null || recipients === void 0 ? void 0 : recipients.length) && (recipients === null || recipients === void 0 ? void 0 : recipients.length) > 1) {
            throw UnsupportedError(`Cannot create ${type} trigger for more than one recipient`);
        }
        [recipient] = recipients;
    }
    return internalLoadById(context, user, recipient);
});
export const addTrigger = (context, user, triggerInput, type) => __awaiter(void 0, void 0, void 0, function* () {
    if (type === TriggerTypeValue.Live && triggerInput.event_types.length === 0) {
        throw UnsupportedError('Attribute "trigger_events" of a live trigger should have at least one event');
    }
    // our stix matching is currently limited, we need to validate the input filters
    const input = triggerInput;
    if (type === TriggerTypeValue.Live && input.filters) {
        const filters = JSON.parse(input.filters);
        validateFilterGroupForStixMatch(filters);
    }
    let authorizedMembers;
    const recipient = yield extractUniqRecipient(context, user, triggerInput, type);
    const isSelfTrigger = recipient.id === user.id;
    if (recipient.entity_type === ENTITY_TYPE_USER) {
        authorizedMembers = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
    }
    else if (recipient.entity_type === ENTITY_TYPE_GROUP || recipient.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
        authorizedMembers = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }];
    }
    else {
        throw UnsupportedError(`Cannot add a recipient with type ${type}`);
    }
    const defaultOpts = {
        trigger_type: type,
        created: now(),
        updated: now(),
        created_at: now(),
        updated_at: now(),
        trigger_scope: 'knowledge',
        instance_trigger: type === TriggerTypeValue.Digest ? false : triggerInput.instance_trigger,
        authorized_members: authorizedMembers,
        authorized_authorities: [SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN] // Add extra capabilities
    };
    const trigger = Object.assign(Object.assign({}, triggerInput), defaultOpts);
    const created = yield createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: isSelfTrigger ? 'extended' : 'administration',
        message: `creates ${type} trigger \`${created.name}\` for ${isSelfTrigger ? '`themselves`' : `\`${recipient.name}\``}`,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
});
export const addTriggerActivity = (context, user, triggerInput, type) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const members = yield internalFindByIds(context, SYSTEM_USER, triggerInput.recipients);
    if (members.length === 0) {
        throw UnsupportedError('Cannot add a activity trigger without recipients');
    }
    // Validate the filter for activity event matching before saving it
    const input = triggerInput;
    if (type === TriggerTypeValue.Live && input.filters) {
        const filters = JSON.parse(input.filters);
        validateFilterGroupForActivityEventMatch(filters);
    }
    const defaultOpts = {
        created: now(),
        updated: now(),
        created_at: now(),
        updated_at: now(),
        trigger_scope: 'activity',
        trigger_type: type,
        authorized_members: [...((_a = triggerInput.recipients) !== null && _a !== void 0 ? _a : []).map((r) => ({ id: r, access_right: MEMBER_ACCESS_RIGHT_VIEW }))],
        authorized_authorities: ['SETTINGS'] // Add extra capabilities
    };
    const trigger = Object.assign(Object.assign({}, triggerInput), defaultOpts);
    const created = yield createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'administration',
        message: `creates ${type} activity trigger \`${created.name}\` for ${members.map((m) => `\`${m.name}\``).join(', ')}`,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
});
export const triggerGet = (context, user, triggerId) => {
    return storeLoadById(context, user, triggerId, ENTITY_TYPE_TRIGGER);
};
// For digest resolutions
export const triggersGet = (context, user, triggerIds) => {
    return internalFindByIds(context, user, triggerIds);
};
export const getTriggerRecipients = (context, user, element) => __awaiter(void 0, void 0, void 0, function* () {
    const access = getUserAccessRight(user, element);
    if (access === MEMBER_ACCESS_RIGHT_ADMIN) {
        const ids = element.authorized_members.map((a) => a.id);
        return internalFindByIds(context, user, ids);
    }
    return [];
});
export const triggerEdit = (context, user, triggerId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const trigger = yield triggerGet(context, user, triggerId);
    if (trigger.trigger_type === TriggerTypeValue.Live) {
        const filtersItem = input.find((item) => item.key === 'filters');
        if (filtersItem === null || filtersItem === void 0 ? void 0 : filtersItem.value[0]) {
            const filterGroup = JSON.parse((filtersItem === null || filtersItem === void 0 ? void 0 : filtersItem.value[0]));
            // filters need to be validated before save, as we are limited in terms of compatible keys
            // this depends if it's an activity live trigger or knowledge live trigger
            if (trigger.trigger_scope === 'knowledge') {
                validateFilterGroupForStixMatch(filterGroup);
            }
            if (trigger.trigger_scope === 'activity') {
                validateFilterGroupForActivityEventMatch(filterGroup);
            }
        }
    }
    const userAccessRight = getUserAccessRight(user, trigger);
    if (userAccessRight === null || ![MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN].includes(userAccessRight)) {
        throw ForbiddenAccess();
    }
    if (trigger.trigger_type === TriggerTypeValue.Live) {
        const emptyTriggerEvents = input.filter((editEntry) => editEntry.key === 'event_types' && editEntry.value.length === 0);
        if (emptyTriggerEvents.length > 0) {
            throw UnsupportedError('Attribute "trigger_events" of a live trigger should have at least one event');
        }
    }
    const { element: updatedElem } = yield updateAttribute(context, user, triggerId, ENTITY_TYPE_TRIGGER, input);
    return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].EDIT_TOPIC, updatedElem, user);
});
export const triggerActivityEdit = (context, user, triggerId, input) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    const finalInput = [];
    for (let index = 0; index < input.length; index += 1) {
        const inputElement = input[index];
        if (inputElement.key === 'recipients') {
            const value = ((_b = inputElement.value) !== null && _b !== void 0 ? _b : []).map((r) => ({ id: r, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
            finalInput.push({ key: 'authorized_members', value });
        }
        else {
            finalInput.push(inputElement);
        }
    }
    return triggerEdit(context, user, triggerId, finalInput);
});
export const triggerDelete = (context, user, triggerId) => __awaiter(void 0, void 0, void 0, function* () {
    var _c, _d, _e, _f;
    const trigger = yield triggerGet(context, user, triggerId);
    const userAccessRight = getUserAccessRight(user, trigger);
    if (userAccessRight !== MEMBER_ACCESS_RIGHT_ADMIN) {
        throw ForbiddenAccess();
    }
    // If user is only organization admin, check if he has access on all targets
    if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
        const memberIds = ((_c = trigger.authorized_members) !== null && _c !== void 0 ? _c : []).map((a) => a.id);
        const adminOrganizationIds = ((_d = user.administrated_organizations) !== null && _d !== void 0 ? _d : []).map((o) => o.internal_id);
        if (!adminOrganizationIds.every((v) => memberIds.includes(v))) {
            throw ForbiddenAccess();
        }
    }
    const adminIds = ((_e = trigger.authorized_members) !== null && _e !== void 0 ? _e : [])
        .filter((a) => a.access_right === 'admin')
        .map((a) => a.id);
    const isSelfTrigger = adminIds.length === 1;
    const deleted = yield deleteElementById(context, user, triggerId, ENTITY_TYPE_TRIGGER);
    const memberIds = ((_f = trigger.authorized_members) !== null && _f !== void 0 ? _f : []).map((a) => a.id);
    const recipients = yield internalFindByIds(context, SYSTEM_USER, memberIds);
    const recipientNames = recipients.map((r) => r.name);
    yield notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].DELETE_TOPIC, deleted, user);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: isSelfTrigger ? 'extended' : 'administration',
        message: `deletes trigger \`${deleted.name}\` for ${isSelfTrigger ? '`themselves`' : `${recipientNames.map((r) => `\`${r}\``).join(', ')}`}`,
        context_data: { id: triggerId, entity_type: ENTITY_TYPE_TRIGGER, input: deleted }
    });
    return triggerId;
});
export const triggersKnowledgeFind = (context, user, opts) => {
    // key is a string[] because of the resolver, we have updated the keys
    const finalFilter = addFilter(opts.filters, 'trigger_scope', 'knowledge');
    const queryArgs = Object.assign(Object.assign({}, opts), { filters: finalFilter });
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};
export const triggersKnowledgeCount = (context, opts) => __awaiter(void 0, void 0, void 0, function* () {
    const finalFilter = addFilter(opts.filters, 'trigger_scope', 'knowledge');
    const queryArgs = Object.assign(Object.assign({}, opts), { filters: finalFilter, types: [ENTITY_TYPE_TRIGGER] });
    return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, queryArgs);
});
export const triggersActivityFind = (context, user, opts) => {
    const finalFilter = addFilter(opts.filters, 'trigger_scope', 'activity');
    const queryArgs = Object.assign(Object.assign({}, opts), { includeAuthorities: true, filters: finalFilter });
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};
// region Notifications
export const notificationGet = (context, user, narrativeId) => {
    return storeLoadById(context, user, narrativeId, ENTITY_TYPE_NOTIFICATION);
};
export const notificationsFind = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_NOTIFICATION], opts);
};
export const myNotificationsFind = (context, user, opts) => {
    const queryFilters = addFilter(opts.filters, 'user_id', user.id);
    const queryArgs = Object.assign(Object.assign({}, opts), { filters: queryFilters });
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_NOTIFICATION], queryArgs);
};
export const myUnreadNotificationsCount = (context, user, userId = null) => __awaiter(void 0, void 0, void 0, function* () {
    const queryFilters = {
        mode: 'and',
        filters: [{ key: 'user_id', values: [userId !== null && userId !== void 0 ? userId : user.id] }, { key: 'is_read', values: [false] }],
        filterGroups: [],
    };
    const queryArgs = { filters: queryFilters, types: [ENTITY_TYPE_NOTIFICATION] };
    return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, queryArgs);
});
export const notificationDelete = (context, user, notificationId) => __awaiter(void 0, void 0, void 0, function* () {
    const notification = yield notificationGet(context, user, notificationId);
    yield deleteElementById(context, user, notificationId, ENTITY_TYPE_NOTIFICATION);
    const unreadNotificationsCount = yield myUnreadNotificationsCount(context, user);
    yield notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: notification.user_id }, user);
    return notificationId;
});
export const notificationEditRead = (context, user, notificationId, read) => __awaiter(void 0, void 0, void 0, function* () {
    const { element } = yield patchAttribute(context, user, notificationId, ENTITY_TYPE_NOTIFICATION, { is_read: read });
    const unreadNotificationsCount = yield myUnreadNotificationsCount(context, user);
    yield notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: element.user_id }, user);
    return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].EDIT_TOPIC, element, user);
});
export const addNotification = (context, user, notification) => __awaiter(void 0, void 0, void 0, function* () {
    const created = yield createEntity(context, user, notification, ENTITY_TYPE_NOTIFICATION);
    const unreadNotificationsCount = yield myUnreadNotificationsCount(context, user, created.user_id);
    yield notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: created.user_id }, user);
    return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].ADDED_TOPIC, created, user);
});
// endregion
