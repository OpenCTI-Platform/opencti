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
import { head } from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { createStreamProcessor, fetchRangeNotifications, lockResource, storeNotificationEvent } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { FunctionalError, TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, INTERNAL_USERS, isUserCanAccessStixElement, isUserCanAccessStoreElement, SYSTEM_USER } from '../utils/access';
import { utcDate } from '../utils/format';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/utils';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { resolveFiltersMapForUser } from '../utils/filtering/filtering-resolution';
import { getEntitiesListFromCache } from '../database/cache';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { extractStixRepresentative } from '../database/stix-representative';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { replaceFilterKey } from '../utils/filtering/filtering-utils';
import { CONNECTED_TO_INSTANCE_FILTER, CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER } from '../utils/filtering/filtering-constants';
const NOTIFICATION_LIVE_KEY = conf.get('notification_manager:lock_live_key');
const NOTIFICATION_DIGEST_KEY = conf.get('notification_manager:lock_digest_key');
export const EVENT_NOTIFICATION_VERSION = '1';
const CRON_SCHEDULE_TIME = 60000; // 1 minute
const STREAM_SCHEDULE_TIME = 10000;
// region: user access information extractors
// extract information from a sighting to have all the elements to check if a user has access to the from/to of the sighting
const extractUserAccessPropertiesFromSighting = (sighting) => {
    return [
        {
            [RELATION_OBJECT_MARKING]: sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_object_marking_refs,
            [RELATION_GRANTED_TO]: sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_granted_refs,
            entity_type: sighting.extensions[STIX_EXT_OCTI].sighting_of_type,
        },
        {
            [RELATION_OBJECT_MARKING]: sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_object_marking_refs,
            [RELATION_GRANTED_TO]: sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_granted_refs,
            entity_type: head(sighting.extensions[STIX_EXT_OCTI].where_sighted_types),
        }
    ];
};
// extract information from a relationship to have all the elements to check if a user has access to the from/to of the relationship
const extractUserAccessPropertiesFromRelationship = (relation) => {
    return [
        {
            [RELATION_OBJECT_MARKING]: relation.extensions[STIX_EXT_OCTI].source_ref_object_marking_refs,
            [RELATION_GRANTED_TO]: relation.extensions[STIX_EXT_OCTI].source_ref_granted_refs,
            entity_type: relation.extensions[STIX_EXT_OCTI].source_type,
        },
        {
            [RELATION_OBJECT_MARKING]: relation.extensions[STIX_EXT_OCTI].target_ref_object_marking_refs,
            [RELATION_GRANTED_TO]: relation.extensions[STIX_EXT_OCTI].target_ref_granted_refs,
            entity_type: relation.extensions[STIX_EXT_OCTI].target_type,
        }
    ];
};
// extract information from a stix object to have all the elements to check if a user has access to the object
const extractUserAccessPropertiesFromStixObject = (instance) => {
    if (isStixSightingRelationship(instance.extensions[STIX_EXT_OCTI].type)) {
        const sighting = instance;
        return extractUserAccessPropertiesFromSighting(sighting);
    }
    if (isStixCoreRelationship(instance.extensions[STIX_EXT_OCTI].type)) {
        const relation = instance;
        return extractUserAccessPropertiesFromRelationship(relation);
    }
    return [];
};
// endregion
export const isLiveKnowledge = (n) => {
    return n.trigger.trigger_scope === 'knowledge' && n.trigger.trigger_type === 'live';
};
export const isDigest = (n) => {
    return n.trigger.trigger_type === 'digest';
};
export const getNotifications = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const triggers = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_TRIGGER);
    const platformUsers = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    return triggers.map((trigger) => {
        var _a, _b;
        const triggerAuthorizedMembersIds = (_b = (_a = trigger.authorized_members) === null || _a === void 0 ? void 0 : _a.map((member) => member.id)) !== null && _b !== void 0 ? _b : [];
        const usersFromGroups = platformUsers.filter((user) => user.groups.map((g) => g.internal_id)
            .some((id) => triggerAuthorizedMembersIds.includes(id)));
        const usersFromOrganizations = platformUsers.filter((user) => user.organizations.map((g) => g.internal_id)
            .some((id) => triggerAuthorizedMembersIds.includes(id)));
        const usersFromIds = platformUsers.filter((user) => triggerAuthorizedMembersIds.includes(user.id));
        const withoutInternalUsers = [...usersFromOrganizations, ...usersFromGroups, ...usersFromIds]
            .filter((u) => INTERNAL_USERS[u.id] === undefined);
        const users = R.uniqBy(R.prop('id'), withoutInternalUsers);
        return { users, trigger };
    });
});
export const getLiveNotifications = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const liveNotifications = yield getNotifications(context);
    return liveNotifications.filter(isLiveKnowledge);
});
export const isTimeTrigger = (digest, baseDate) => {
    const now = baseDate.clone().startOf('minutes'); // 2022-11-25T19:11:00.000Z
    const { trigger } = digest;
    const triggerTime = trigger.trigger_time;
    switch (trigger.period) {
        case 'hour': {
            // Need to check if time is aligned on the perfect hour
            const nowHourAlign = now.clone().startOf('hours');
            return now.isSame(nowHourAlign);
        }
        case 'day': {
            // Need to check if time is aligned on the day hour (like 19:11:00.000Z)
            const dayTime = `${now.clone().format('HH:mm:ss.SSS')}Z`;
            return triggerTime === dayTime;
        }
        case 'week': {
            // Need to check if time is aligned on the week hour (like 1-19:11:00.000Z)
            // 1 being Monday and 7 being Sunday.
            const weekTime = `${now.clone().isoWeekday()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
            return triggerTime === weekTime;
        }
        case 'month': {
            // Need to check if time is aligned on the month hour (like 22-19:11:00.000Z)
            const monthTime = `${now.clone().date()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
            return triggerTime === monthTime;
        }
        default:
            return false;
    }
};
export const getDigestNotifications = (context, baseDate) => __awaiter(void 0, void 0, void 0, function* () {
    const notifications = yield getNotifications(context);
    return notifications.filter(isDigest).filter((digest) => isTimeTrigger(digest, baseDate));
});
export const convertToNotificationUser = (user, notifiers) => {
    return {
        user_id: user.internal_id,
        user_email: user.user_email,
        notifiers,
    };
};
// indicates if a relation from/to contains an instance that is in an instances map
export const isRelationFromOrToMatchFilters = (listenedInstanceIdsMap, instance) => {
    const stixIdsToSearch = [];
    if (instance.type === STIX_TYPE_SIGHTING) {
        stixIdsToSearch.push(instance.sighting_of_ref, ...instance.where_sighted_refs);
    }
    else if (instance.type === STIX_TYPE_RELATION) {
        stixIdsToSearch.push(instance.source_ref, instance.target_ref);
    }
    // eslint-disable-next-line no-restricted-syntax
    for (const value of listenedInstanceIdsMap.values()) {
        if (stixIdsToSearch.includes(value.id)) {
            return true;
        }
    }
    return false;
};
// keep only the refs event ids that are in the map of the listened instances
const filterInstancesByRefEventIds = (listenedInstanceIdsMap, refsEventIds) => {
    const instances = [];
    refsEventIds.forEach((refId) => {
        const instance = listenedInstanceIdsMap.get(refId);
        if (instance) {
            instances.push(instance);
        }
    });
    return instances;
};
// generate an array of the instances that are in patch/reverse_patch and in the map of the listened instances
// with the indication, for each instance, if there are in the patch ('added in') or in the reverse_patch ('removed from')
export const filterUpdateInstanceIdsFromUpdatePatch = (listenedInstanceIdsMap, updatePatch) => {
    const addedIds = updatePatch.patch
        .map((n) => n.value)
        .flat()
        .filter((n) => n);
    const removedIds = updatePatch.reverse_patch
        .map((n) => n.value)
        .flat()
        .filter((n) => n);
    const instances = [];
    addedIds.forEach((id) => {
        if (listenedInstanceIdsMap.has(id)) {
            instances.push({
                instance: listenedInstanceIdsMap.get(id),
                action: 'added in',
            });
        }
    });
    removedIds.forEach((id) => {
        if (listenedInstanceIdsMap.has(id)) {
            instances.push({
                instance: listenedInstanceIdsMap.get(id),
                action: 'removed from',
            });
        }
    });
    return instances;
};
const eventTypeTranslater = (isPreviousMatch, isCurrentlyMatch, currentType) => {
    if (isPreviousMatch && !isCurrentlyMatch) { // No longer visible
        return EVENT_TYPE_DELETE;
    }
    if (!isPreviousMatch && isCurrentlyMatch) { // Newly visible
        return EVENT_TYPE_CREATE;
    }
    return currentType;
};
const eventTypeTranslaterForSideEvents = (context, user, isPreviousMatch, isCurrentlyMatch, currentType, previousInstance, instance, listenedInstanceIdsMap, updatePatch) => __awaiter(void 0, void 0, void 0, function* () {
    // 1. case update, we should check the updatePatch content
    if (currentType === EVENT_TYPE_UPDATE && updatePatch) {
        // 1.a. we should first check if the visibility of the instance has changed for the user
        // (to deal with cases of update of both a ref linked to rights (markings/granted_refs) and sth else)
        const previouslyVisible = yield isUserCanAccessStixElement(context, user, previousInstance);
        const currentlyVisible = yield isUserCanAccessStixElement(context, user, instance);
        // - the visiblity has changed: display a changing of rights, don't take the eventual changed refs into account
        if (previouslyVisible !== currentlyVisible) {
            return eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, currentType); // case modification of rights (newly/no more visible)
        }
        // - the visibility has not changed: eventually display an update of refs (-> go to case 1.b.)
        // 1.b. update of a ref without rights modification
        const listenedInstancesInPatchIds = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, updatePatch);
        if (listenedInstancesInPatchIds.length > 0) { // update of a ref that is in the listened instances
            return EVENT_TYPE_UPDATE;
        }
    }
    // 2. case modification of rights (newly/no more visible)
    return eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, currentType);
});
// generate a notification message for an instance
// taking the user rights into account in case of a relationship (from/to restricted or not)
export const generateNotificationMessageForInstance = (context, user, instance) => __awaiter(void 0, void 0, void 0, function* () {
    const [from, to] = extractUserAccessPropertiesFromStixObject(instance);
    const fromRestricted = from ? !(yield isUserCanAccessStoreElement(context, user, from)) : false;
    const toRestricted = to ? !(yield isUserCanAccessStoreElement(context, user, to)) : false;
    const instanceRepresentative = extractStixRepresentative(instance, { fromRestricted, toRestricted });
    return `[${instance.type.toLowerCase()}] ${instanceRepresentative}`;
});
// generate a notification message with an instance and refs - case creation/deletion
export const generateNotificationMessageForInstanceWithRefs = (context, user, instance, refsInstances) => __awaiter(void 0, void 0, void 0, function* () {
    const mainInstanceMessage = yield generateNotificationMessageForInstance(context, user, instance);
    return `${mainInstanceMessage} containing ${refsInstances.map((ref) => `[${ref.type.toLowerCase()}] ${extractStixRepresentative(ref)}`)}`;
});
// generate a notification message with an instance and refs - case update
export const generateNotificationMessageForInstanceWithRefsUpdate = (context, user, instance, refsInstances) => __awaiter(void 0, void 0, void 0, function* () {
    const mainInstanceMessage = yield generateNotificationMessageForInstance(context, user, instance);
    const groupedRefsInstances = Object.values(R.groupBy((ref) => ref.action, refsInstances)); // refs instances grouped by notification message
    return `${groupedRefsInstances
        .map((refsGroup) => {
        var _a, _b;
        return `${(refsGroup || [])
            .map((ref) => `[${ref.instance.type.toLowerCase()}] ${extractStixRepresentative(ref.instance)}`)} ${(_b = (_a = (refsGroup || [])[0]) === null || _a === void 0 ? void 0 : _a.action) !== null && _b !== void 0 ? _b : 'unknown'} ${mainInstanceMessage}`;
    })}`;
});
// generate the message to display in the notification for filtered instance trigger side events
const generateNotificationMessageForFilteredSideEvents = (context, user, data, frontendFilters, translatedType, updatePatch, previousData) => __awaiter(void 0, void 0, void 0, function* () {
    // Get ids from the user trigger filters that user has access to
    const listenedInstanceIdsMap = yield resolveFiltersMapForUser(context, user, frontendFilters);
    // -- 01. Notification for relationships (creation/deletion/newly visible/no more visible)
    if ([STIX_TYPE_RELATION, STIX_TYPE_SIGHTING].includes(data.type) // the event is a relationship
        && isRelationFromOrToMatchFilters(listenedInstanceIdsMap, data) // and the relationship from/to contains an instance of the trigger filters
        && translatedType !== EVENT_TYPE_UPDATE // if displayed type is update, we should have notifications in case a listened instance is in the patch (= case 1.2.)
    ) {
        // User should be notified of the relationship creation / deletion / newly visible / no more visible
        return generateNotificationMessageForInstance(context, user, data);
    }
    // -- 02. translatedType = update (i.e. event type = update that modify a listened ref and doesn't modify the rights)
    if (translatedType === EVENT_TYPE_UPDATE) {
        if (!updatePatch) {
            throw FunctionalError('An event of type update should have an update patch');
        }
        const listenedInstancesInPatchIds = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, updatePatch);
        if (listenedInstancesInPatchIds.length > 0) { // 2.a.--> It's the patch that contains instance(s) of the trigger filters
            const message = yield generateNotificationMessageForInstanceWithRefsUpdate(context, user, data, listenedInstancesInPatchIds);
            return message;
        }
        // the modification may be a modification of rights (the instance is newly/no-more visible) -> we go in case 3.
    }
    // -- 03. --> Newly/no more visible instance containing listened refs
    // It's the data refs that contain instance(s) of the trigger filters (translatedType = create/delete)
    // we don't want updates that doesn't involve a modification of rights (ex: modification of the description of an entity that has listened instances in its refs)
    if (translatedType !== EVENT_TYPE_UPDATE) {
        // fetch the instance data refs
        // -case instance no more visible : fetch data refs before the modifications -> data refs of 'previousData'
        // -else (ie newly visible instance / creation / deletion): fetch data refs after the modification / at creation / at deletion -> data refs of 'data'
        const dataRefs = (translatedType === EVENT_TYPE_DELETE && previousData) ? stixRefsExtractor(previousData) : stixRefsExtractor(data);
        // We need to filter these instances to keep those that are part of the event refs or of the relationship from/to
        const listenedInstancesInRefsEventIds = filterInstancesByRefEventIds(listenedInstanceIdsMap, dataRefs);
        if (listenedInstancesInRefsEventIds.length > 0) {
            const message = yield generateNotificationMessageForInstanceWithRefs(context, user, data, listenedInstancesInRefsEventIds);
            return message;
        }
    }
    return undefined; // filtered event (ex: update of an instance containing a listened ref) : no notification
});
export const buildTargetEvents = (context, users, streamEvent, trigger, useSideEventMatching = false) => __awaiter(void 0, void 0, void 0, function* () {
    const { data: { data }, event: eventType } = streamEvent;
    const { event_types, notifiers, instance_trigger, filters } = trigger;
    let finalFilters = filters ? JSON.parse(filters) : null;
    if (useSideEventMatching) { // modify filters to look for instance trigger side events
        finalFilters = replaceFilterKey(JSON.parse(trigger.filters), CONNECTED_TO_INSTANCE_FILTER, CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER);
    }
    let triggerEventTypes = event_types;
    if (instance_trigger && event_types.includes(EVENT_TYPE_UPDATE)) {
        triggerEventTypes = useSideEventMatching
            ? [EVENT_TYPE_UPDATE, EVENT_TYPE_CREATE, EVENT_TYPE_DELETE] // extends trigger event types for side events search
            : [...event_types, EVENT_TYPE_CREATE]; // create is always included for instance_triggers with update in their event_types
    }
    const targets = [];
    if (eventType === EVENT_TYPE_UPDATE) {
        const { context: updatePatch } = streamEvent.data;
        const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(data), updatePatch.reverse_patch);
        for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
            // For each user for a specific trigger
            const user = users[indexUser];
            const notificationUser = convertToNotificationUser(user, notifiers);
            // TODO: replace with new matcher, but handle side events
            // Check if the event matched/matches the trigger filters and the user rights
            const isPreviousMatch = yield isStixMatchFilterGroup(context, user, previous, finalFilters);
            const isCurrentlyMatch = yield isStixMatchFilterGroup(context, user, data, finalFilters);
            // Depending on the previous visibility, the displayed event type will be different
            if (!useSideEventMatching) { // Case classic live trigger & instance trigger direct events: user should be notified of the direct event
                const translatedType = eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, eventType);
                // Case 01. No longer visible because of a data update (user loss of rights OR instance_trigger & remove a listened instance in the refs)
                if (isPreviousMatch && !isCurrentlyMatch && triggerEventTypes.includes(translatedType)) { // translatedType = delete
                    const message = yield generateNotificationMessageForInstance(context, user, data);
                    targets.push({ user: notificationUser, type: translatedType, message });
                }
                else 
                // Case 02. Newly visible because of a data update (gain of rights OR instance_trigger & add a listened instance in the refs)
                if (!isPreviousMatch && isCurrentlyMatch && triggerEventTypes.includes(translatedType)) { // translated type = create
                    const message = yield generateNotificationMessageForInstance(context, user, data);
                    targets.push({ user: notificationUser, type: translatedType, message });
                }
                else if (isCurrentlyMatch && triggerEventTypes.includes(translatedType)) {
                    // Case 03. Just an update
                    const message = yield generateNotificationMessageForInstance(context, user, data);
                    targets.push({ user: notificationUser, type: translatedType, message });
                }
            }
            else { // useSideEventMatching = true: Case side events for instance triggers
                // eslint-disable-next-line no-lonely-if
                if (isPreviousMatch || isCurrentlyMatch) { // we keep events if : was visible and/or is visible
                    const listenedInstanceIdsMap = yield resolveFiltersMapForUser(context, user, finalFilters);
                    // eslint-disable-next-line max-len
                    const translatedType = yield eventTypeTranslaterForSideEvents(context, user, isPreviousMatch, isCurrentlyMatch, eventType, previous, data, listenedInstanceIdsMap, updatePatch);
                    const message = yield generateNotificationMessageForFilteredSideEvents(context, user, data, finalFilters, translatedType, updatePatch, previous);
                    if (message) {
                        targets.push({ user: notificationUser, type: translatedType, message });
                    }
                }
            }
        }
    }
    else if (triggerEventTypes.includes(eventType)) { // create or delete
        for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
            const user = users[indexUser];
            const notificationUser = convertToNotificationUser(user, notifiers);
            const isCurrentlyMatch = yield isStixMatchFilterGroup(context, user, data, finalFilters);
            if (isCurrentlyMatch) {
                if (!useSideEventMatching) { // classic live trigger or instance trigger with direct event
                    const message = yield generateNotificationMessageForInstance(context, user, data);
                    targets.push({ user: notificationUser, type: eventType, message });
                }
                else { // instance trigger side events
                    const message = yield generateNotificationMessageForFilteredSideEvents(context, user, data, finalFilters, eventType);
                    if (message) {
                        targets.push({ user: notificationUser, type: eventType, message });
                    }
                }
            }
        }
    }
    return targets;
});
const notificationLiveStreamHandler = (streamEvents) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        if (streamEvents.length === 0) {
            return;
        }
        const context = executionContext('notification_manager');
        const liveNotifications = yield getLiveNotifications(context);
        for (let index = 0; index < streamEvents.length; index += 1) {
            const streamEvent = streamEvents[index];
            const { data: { data } } = streamEvent;
            // For each event we need to check ifs
            for (let notifIndex = 0; notifIndex < liveNotifications.length; notifIndex += 1) {
                const { users, trigger } = liveNotifications[notifIndex];
                const { internal_id: notification_id, trigger_type: type, instance_trigger } = trigger;
                const targets = yield buildTargetEvents(context, users, streamEvent, trigger);
                if (targets.length > 0) {
                    const version = EVENT_NOTIFICATION_VERSION;
                    const notificationEvent = { version, notification_id, type, targets, data };
                    yield storeNotificationEvent(context, notificationEvent);
                }
                // search side events for instance_trigger
                if (instance_trigger && trigger.event_types.includes(EVENT_TYPE_UPDATE)) {
                    const sideTargets = yield buildTargetEvents(context, users, streamEvent, trigger, true);
                    if (sideTargets.length > 0) {
                        const version = EVENT_NOTIFICATION_VERSION;
                        const notificationEvent = { version, notification_id, type, targets: sideTargets, data };
                        yield storeNotificationEvent(context, notificationEvent);
                    }
                }
            }
        }
    }
    catch (e) {
        logApp.error(e, { manager: 'NOTIFICATION_MANAGER' });
    }
});
const handleDigestNotifications = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const baseDate = utcDate().startOf('minutes');
    // Get digest that need to be executed
    const digestNotifications = yield getDigestNotifications(context, baseDate);
    // Iter on each digest and generate the output
    for (let index = 0; index < digestNotifications.length; index += 1) {
        const { trigger, users } = digestNotifications[index];
        const { period, trigger_ids: triggerIds, notifiers, internal_id: notification_id, trigger_type: type } = trigger;
        const fromDate = baseDate.clone().subtract(1, period).toDate();
        const rangeNotifications = yield fetchRangeNotifications(fromDate, baseDate.toDate());
        const digestContent = rangeNotifications.filter((n) => triggerIds.includes(n.notification_id));
        if (digestContent.length > 0) {
            // Range of results must filtered to keep only data related to the digest
            // And related to the users participating to the digest
            for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
                const user = users[userIndex];
                const userNotifications = digestContent.filter((d) => d.targets
                    .map((t) => t.user.user_id).includes(user.internal_id));
                if (userNotifications.length > 0) {
                    const version = EVENT_NOTIFICATION_VERSION;
                    const target = convertToNotificationUser(user, notifiers);
                    const dataPromises = userNotifications.map((n) => __awaiter(void 0, void 0, void 0, function* () {
                        var _a;
                        const userTarget = n.targets.find((t) => t.user.user_id === user.internal_id);
                        return ({
                            notification_id: n.notification_id,
                            type: (_a = userTarget === null || userTarget === void 0 ? void 0 : userTarget.type) !== null && _a !== void 0 ? _a : type,
                            instance: n.data,
                            message: yield generateNotificationMessageForInstance(context, user, n.data),
                        });
                    }));
                    const data = yield Promise.all(dataPromises);
                    const digestEvent = { version, notification_id, type, target, data };
                    yield storeNotificationEvent(context, digestEvent);
                }
            }
        }
    }
});
const initNotificationManager = () => {
    const WAIT_TIME_ACTION = 2000;
    let streamScheduler;
    let cronScheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const notificationLiveHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([NOTIFICATION_LIVE_KEY], { retryCount: 0 });
            running = true;
            logApp.info('[OPENCTI-MODULE] Running notification manager (live)');
            streamProcessor = createStreamProcessor(SYSTEM_USER, 'Notification manager', notificationLiveStreamHandler);
            yield streamProcessor.start('live');
            while (!shutdown && streamProcessor.running()) {
                lock.signal.throwIfAborted();
                yield wait(WAIT_TIME_ACTION);
            }
            logApp.info('[OPENCTI-MODULE] End of notification manager processing (live)');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-MODULE] Notification manager already started by another API');
            }
            else {
                logApp.error(e, { manager: 'NOTIFICATION_MANAGER' });
            }
        }
        finally {
            if (streamProcessor)
                yield streamProcessor.shutdown();
            if (lock)
                yield lock.unlock();
        }
    });
    const notificationDigestHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('notification_manager');
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([NOTIFICATION_DIGEST_KEY], { retryCount: 0 });
            logApp.info('[OPENCTI-MODULE] Running notification manager (digest)');
            while (!shutdown) {
                lock.signal.throwIfAborted();
                yield handleDigestNotifications(context);
                yield wait(CRON_SCHEDULE_TIME);
            }
            logApp.info('[OPENCTI-MODULE] End of notification manager processing (digest)');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-MODULE] Notification manager (digest) already started by another API');
            }
            else {
                logApp.error(e, { manager: 'NOTIFICATION_MANAGER' });
            }
        }
        finally {
            if (lock)
                yield lock.unlock();
        }
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            streamScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield notificationLiveHandler();
            }), STREAM_SCHEDULE_TIME);
            cronScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield notificationDigestHandler();
            }), CRON_SCHEDULE_TIME);
        }),
        status: () => {
            return {
                id: 'NOTIFICATION_MANAGER',
                enable: booleanConf('notification_manager:enabled', false),
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping notification manager');
            shutdown = true;
            if (streamScheduler)
                yield clearIntervalAsync(streamScheduler);
            if (cronScheduler)
                yield clearIntervalAsync(cronScheduler);
            return true;
        }),
    };
};
const notificationManager = initNotificationManager();
export default notificationManager;
