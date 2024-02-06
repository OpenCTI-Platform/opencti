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
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import * as jsonpatch from 'fast-json-patch';
import { createStreamProcessor, lockResource } from '../database/redis';
import conf, { booleanConf, ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { EVENT_TYPE_UPDATE, INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, REDACTED_USER, SYSTEM_USER } from '../utils/access';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { utcDate } from '../utils/format';
import { elIndexElements } from '../database/engine';
import { listEntities } from '../database/middleware-loader';
import { BASE_TYPE_ENTITY, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../database/cache';
import { FilterMode, FilterOperator, OrderingMode } from '../generated/graphql';
import { extractStixRepresentative } from '../database/stix-representative';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
const HISTORY_ENGINE_KEY = conf.get('history_manager:lock_key');
const HISTORY_WITH_INFERENCES = booleanConf('history_manager:include_inferences', false);
const SCHEDULE_TIME = 10000;
const eventsApplyHandler = (context, events) => __awaiter(void 0, void 0, void 0, function* () {
    if (isEmptyField(events) || events.length === 0) {
        return;
    }
    const markingsById = yield getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
    const organizationsById = yield getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    // Build the history data
    const historyElements = events.map((event) => {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r;
        const [time] = event.id.split('-');
        const eventDate = utcDate(parseInt(time, 10)).toISOString();
        const stix = event.data.data;
        const eventMarkingRefs = ((_a = stix.object_marking_refs) !== null && _a !== void 0 ? _a : [])
            .map((stixId) => { var _a; return (_a = markingsById.get(stixId)) === null || _a === void 0 ? void 0 : _a.internal_id; })
            .filter((o) => isNotEmptyField(o));
        const eventGrantedRefs = ((_b = stix.extensions[STIX_EXT_OCTI].granted_refs) !== null && _b !== void 0 ? _b : [])
            .map((stixId) => { var _a; return (_a = organizationsById.get(stixId)) === null || _a === void 0 ? void 0 : _a.internal_id; })
            .filter((o) => isNotEmptyField(o));
        const contextData = {
            id: stix.extensions[STIX_EXT_OCTI].id,
            message: event.data.message,
            entity_type: stix.extensions[STIX_EXT_OCTI].type,
            entity_name: extractStixRepresentative(stix),
            creator_ids: stix.extensions[STIX_EXT_OCTI].creator_ids
        };
        if (event.data.type === EVENT_TYPE_UPDATE) {
            const updateEvent = event.data;
            contextData.commit = (_c = updateEvent.commit) === null || _c === void 0 ? void 0 : _c.message;
            contextData.external_references = (_e = (_d = updateEvent.commit) === null || _d === void 0 ? void 0 : _d.external_references) !== null && _e !== void 0 ? _e : [];
            // Previous markings must be kept to ensure data visibility restrictions
            const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(stix), updateEvent.context.reverse_patch);
            const previousMarkingRefs = ((_f = previous.object_marking_refs) !== null && _f !== void 0 ? _f : [])
                .map((stixId) => { var _a; return (_a = markingsById.get(stixId)) === null || _a === void 0 ? void 0 : _a.internal_id; })
                .filter((o) => isNotEmptyField(o));
            eventMarkingRefs.push(...previousMarkingRefs);
        }
        if (stix.type === STIX_TYPE_RELATION) {
            const rel = stix;
            contextData.from_id = rel.extensions[STIX_EXT_OCTI].source_ref;
            contextData.to_id = rel.extensions[STIX_EXT_OCTI].target_ref;
            // Markings of the source/target must be taken into account to ensure data visibility restrictions
            eventMarkingRefs.push(...((_g = rel.extensions[STIX_EXT_OCTI].source_ref_object_marking_refs) !== null && _g !== void 0 ? _g : []));
            eventMarkingRefs.push(...((_h = rel.extensions[STIX_EXT_OCTI].target_ref_object_marking_refs) !== null && _h !== void 0 ? _h : []));
        }
        if (stix.type === STIX_TYPE_SIGHTING) {
            const sighting = stix;
            contextData.from_id = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref;
            contextData.to_id = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_refs);
            // Markings of the source/target must be taken into account to ensure data visibility restrictions
            eventMarkingRefs.push(...((_j = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_object_marking_refs) !== null && _j !== void 0 ? _j : []));
            eventMarkingRefs.push(...((_k = sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_object_marking_refs) !== null && _k !== void 0 ? _k : []));
        }
        const activityDate = utcDate(eventDate).toDate();
        const standardId = generateStandardId(ENTITY_TYPE_HISTORY, { internal_id: event.id });
        return {
            _index: INDEX_HISTORY,
            internal_id: event.id,
            standard_id: standardId,
            base_type: BASE_TYPE_ENTITY,
            created_at: activityDate,
            updated_at: activityDate,
            entity_type: ENTITY_TYPE_HISTORY,
            event_type: 'mutation',
            event_scope: event.event,
            user_id: ENABLED_DEMO_MODE ? REDACTED_USER.id : (_l = event.data.origin) === null || _l === void 0 ? void 0 : _l.user_id,
            group_ids: (_o = (_m = event.data.origin) === null || _m === void 0 ? void 0 : _m.group_ids) !== null && _o !== void 0 ? _o : [],
            organization_ids: (_q = (_p = event.data.origin) === null || _p === void 0 ? void 0 : _p.organization_ids) !== null && _q !== void 0 ? _q : [],
            applicant_id: (_r = event.data.origin) === null || _r === void 0 ? void 0 : _r.applicant_id,
            timestamp: eventDate,
            context_data: contextData,
            authorized_members: stix.extensions[STIX_EXT_OCTI].authorized_members,
            'rel_object-marking.internal_id': R.uniq(eventMarkingRefs),
            'rel_granted.internal_id': R.uniq(eventGrantedRefs)
        };
    });
    // Bulk the history data insertions
    yield elIndexElements(context, SYSTEM_USER, `history (${historyElements.length})`, historyElements);
});
const historyStreamHandler = (streamEvents) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // Create list of events to process
        // Events must be in a compatible version and not inferences events
        // Inferences directly handle recursively by the manager
        const compatibleEvents = streamEvents.filter((event) => {
            var _a, _b, _c, _d;
            const isInference = (_b = (_a = event.data) === null || _a === void 0 ? void 0 : _a.data) === null || _b === void 0 ? void 0 : _b.extensions[STIX_EXT_OCTI].is_inferred;
            const validEvent = HISTORY_WITH_INFERENCES || !isInference;
            const eventVersion = parseInt((_d = (_c = event.data) === null || _c === void 0 ? void 0 : _c.version) !== null && _d !== void 0 ? _d : '0', 10);
            return eventVersion >= 4 && validEvent;
        });
        if (compatibleEvents.length > 0) {
            // Execute the events
            const context = executionContext('history_manager');
            yield eventsApplyHandler(context, compatibleEvents);
        }
    }
    catch (e) {
        logApp.error(e, { manager: 'HISTORY_MANAGER' });
    }
});
const initHistoryManager = () => {
    const WAIT_TIME_ACTION = 2000;
    let scheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const historyHandler = (lastEventId) => __awaiter(void 0, void 0, void 0, function* () {
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([HISTORY_ENGINE_KEY], { retryCount: 0 });
            running = true;
            logApp.info('[OPENCTI-MODULE] Running history manager');
            streamProcessor = createStreamProcessor(SYSTEM_USER, 'History manager', historyStreamHandler);
            yield streamProcessor.start(lastEventId);
            while (!shutdown && streamProcessor.running()) {
                lock.signal.throwIfAborted();
                yield wait(WAIT_TIME_ACTION);
            }
            logApp.info('[OPENCTI-MODULE] End of history manager processing');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-MODULE] History manager already started by another API');
            }
            else {
                logApp.error(e, { manager: 'HISTORY_MANAGER' });
            }
        }
        finally {
            running = false;
            if (streamProcessor)
                yield streamProcessor.shutdown();
            if (lock)
                yield lock.unlock();
        }
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            // To start the manager we need to find the last event id indexed
            // and restart the stream consumption from this point.
            const context = executionContext('history_manager');
            const histoElements = yield listEntities(context, SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
                first: 1,
                indices: [INDEX_HISTORY],
                connectionFormat: false,
                orderBy: ['timestamp'],
                orderMode: OrderingMode.Desc,
                filters: {
                    mode: FilterMode.And,
                    filters: [{ key: ['event_access'], values: [], operator: FilterOperator.Nil }],
                    filterGroups: [],
                },
                noFiltersChecking: true
            });
            let lastEventId = '0-0';
            if (histoElements.length > 0) {
                const histoDate = histoElements[0].timestamp;
                lastEventId = `${utcDate(histoDate).unix() * 1000}-0`;
            }
            // Start the listening of events
            scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield historyHandler(lastEventId);
            }), SCHEDULE_TIME);
        }),
        status: () => {
            return {
                id: 'HISTORY_MANAGER',
                enable: booleanConf('history_manager:enabled', false),
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping history manager');
            shutdown = true;
            if (scheduler) {
                yield clearIntervalAsync(scheduler);
            }
            return true;
        }),
    };
};
const historyManager = initHistoryManager();
export default historyManager;
