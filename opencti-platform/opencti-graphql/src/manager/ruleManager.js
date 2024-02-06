var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* eslint-disable camelcase */
import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { createStreamProcessor, EVENT_CURRENT_VERSION, lockResource, REDIS_STREAM_NAME } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { createEntity, patchAttribute, stixLoadById, storeLoadByIdWithRefs } from '../database/middleware';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE, isEmptyField, isNotEmptyField, READ_DATA_INDICES } from '../database/utils';
import { RULE_PREFIX } from '../schema/general';
import { ENTITY_TYPE_RULE_MANAGER } from '../schema/internalObject';
import { ALREADY_DELETED_ERROR, TYPE_LOCK_ERROR } from '../config/errors';
import { getParentTypes } from '../schema/schemaUtils';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { internalLoadById } from '../database/middleware-loader';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { getActivatedRules, RULES_DECLARATION } from '../domain/rules';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
import { isModuleActivated } from '../domain/settings';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { elList } from '../database/engine';
const MIN_LIVE_STREAM_EVENT_VERSION = 4;
// let activatedRules: Array<RuleRuntime> = [];
const RULE_ENGINE_ID = 'rule_engine_settings';
const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');
const SCHEDULE_TIME = 10000;
export const getManagerInfo = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const isRuleEngineActivated = yield isModuleActivated('RULE_ENGINE');
    const ruleStatus = yield internalLoadById(context, user, RULE_ENGINE_ID);
    return Object.assign({ activated: isRuleEngineActivated }, ruleStatus);
});
export const buildInternalEvent = (type, stix) => {
    return {
        version: EVENT_CURRENT_VERSION,
        type,
        scope: 'internal',
        message: 'rule internal event',
        origin: RULE_MANAGER_USER,
        data: stix,
    };
};
const ruleMergeHandler = (context, event) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    const { data, context: eventContext } = event;
    const events = [];
    // region 01 - Generate events for deletion
    // -- sources
    const sourceDeleteEvents = (eventContext.sources || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
    events.push(...sourceDeleteEvents);
    // -- derived deletions
    const derivedDeleteEvents = (eventContext.deletions || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
    events.push(...derivedDeleteEvents);
    // endregion
    // region 02 - Generate events for shifted relations
    if (((_a = eventContext.shifts) !== null && _a !== void 0 ? _a : []).length > 0) {
        const shifts = (_b = eventContext.shifts) !== null && _b !== void 0 ? _b : [];
        for (let index = 0; index < shifts.length; index += 1) {
            const shift = shifts[index];
            const shiftedElement = yield stixLoadById(context, RULE_MANAGER_USER, shift);
            // In past reprocess the shift element can already have been deleted.
            if (shiftedElement) {
                // We need to clean the element associated with this relation and then rescan it
                events.push(buildInternalEvent(EVENT_TYPE_DELETE, shiftedElement));
                // Then we need to generate event for redo rule on shifted relations
                events.push(buildInternalEvent(EVENT_TYPE_CREATE, shiftedElement));
            }
        }
    }
    // endregion
    // region 03 - Generate event for merged entity
    const updateEvent = buildInternalEvent(EVENT_TYPE_UPDATE, data);
    updateEvent.context = { patch: eventContext.patch, reverse_patch: eventContext.reverse_patch };
    events.push(updateEvent);
    // endregion
    return events;
});
const isAttributesImpactDependencies = (rule, operations) => {
    var _a;
    const rulesAttributes = ((_a = rule.scopes) !== null && _a !== void 0 ? _a : [])
        .map((s) => s.attributes)
        .flat()
        .filter((a) => a.dependency === true)
        .map((a) => a.name);
    const operationAttributes = R.uniq(operations.map((o) => {
        const parts = o.path.substring(1).split('/');
        // eslint-disable-next-line no-restricted-globals
        return parts.filter((p) => isNaN(Number(p))).join('.');
    }));
    return operationAttributes.filter((f) => rulesAttributes.includes(f)).length > 0;
};
const isMatchRuleScope = (scopeFilter, element) => {
    const { filters } = scopeFilter;
    const { types = [], fromTypes = [], toTypes = [] } = filters !== null && filters !== void 0 ? filters : {};
    const instanceType = element.extensions[STIX_EXT_OCTI].type;
    if (types.length > 0) {
        const elementTypes = [instanceType, ...getParentTypes(instanceType)];
        const isCompatibleType = types.some((r) => elementTypes.includes(r));
        if (!isCompatibleType) {
            return false;
        }
    }
    if (isBasicRelationship(instanceType)) {
        const isSighting = isStixSightingRelationship(instanceType);
        let fromType;
        let toType;
        if (isSighting) {
            const sighting = element;
            fromType = sighting.extensions[STIX_EXT_OCTI].sighting_of_type;
            toType = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_types);
        }
        else {
            const relation = element;
            fromType = relation.extensions[STIX_EXT_OCTI].source_type;
            toType = relation.extensions[STIX_EXT_OCTI].target_type;
        }
        if (fromTypes.length > 0) {
            const instanceFromTypes = [fromType, ...getParentTypes(fromType)];
            const isCompatibleType = fromTypes.some((r) => instanceFromTypes.includes(r));
            if (!isCompatibleType) {
                return false;
            }
        }
        if (toTypes.length > 0) {
            const instanceToTypes = [toType, ...getParentTypes(toType)];
            const isCompatibleType = toTypes.some((r) => instanceToTypes.includes(r));
            if (!isCompatibleType) {
                return false;
            }
        }
    }
    return true;
};
const isMatchRuleFilters = (rule, element) => {
    var _a;
    // Handle types filtering
    const evaluations = [];
    const scopeFilters = (_a = rule.scopes) !== null && _a !== void 0 ? _a : [];
    for (let index = 0; index < scopeFilters.length; index += 1) {
        const scopeFilter = scopeFilters[index];
        evaluations.push(isMatchRuleScope(scopeFilter, element));
    }
    // All filters are valid
    return evaluations.reduce((a, b) => a || b);
};
const handleRuleError = (event, error) => __awaiter(void 0, void 0, void 0, function* () {
    const { type } = event;
    logApp.error(error, { event, type });
});
const applyCleanupOnDependencyIds = (deletionIds) => __awaiter(void 0, void 0, void 0, function* () {
    const context = executionContext('rule_cleaner', RULE_MANAGER_USER);
    const filters = {
        mode: FilterMode.And,
        filters: [{ key: [`${RULE_PREFIX}*.dependencies`], values: deletionIds, operator: FilterOperator.Wildcard }],
        filterGroups: [],
    };
    const callback = (elements) => __awaiter(void 0, void 0, void 0, function* () {
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        yield rulesCleanHandler(context, RULE_MANAGER_USER, elements, RULES_DECLARATION, deletionIds);
    });
    const opts = { filters, noFiltersChecking: true, callback };
    yield elList(context, RULE_MANAGER_USER, READ_DATA_INDICES, opts);
});
export const rulesApplyHandler = (context, user, events, forRules = []) => __awaiter(void 0, void 0, void 0, function* () {
    var _c, _d;
    if (isEmptyField(events) || events.length === 0) {
        return;
    }
    const rules = forRules.length > 0 ? forRules : yield getActivatedRules(context, user);
    // Execute the events
    for (let index = 0; index < events.length; index += 1) {
        const event = events[index];
        const { type, data } = event;
        try {
            // In case of merge convert the events to basic events and restart the process
            if (type === EVENT_TYPE_MERGE) {
                const mergeEvent = event;
                const mergeEvents = yield ruleMergeHandler(context, mergeEvent);
                // eslint-disable-next-line @typescript-eslint/no-use-before-define
                yield rulesApplyHandler(context, user, mergeEvents);
            }
            // In case of deletion, call clean on every impacted elements
            if (type === EVENT_TYPE_DELETE) {
                const deleteEvent = event;
                const internalId = deleteEvent.data.extensions[STIX_EXT_OCTI].id;
                const contextDeletionsIds = ((_d = (_c = deleteEvent.context) === null || _c === void 0 ? void 0 : _c.deletions) !== null && _d !== void 0 ? _d : []).map((d) => d.extensions[STIX_EXT_OCTI].id);
                const deletionIds = [internalId, ...contextDeletionsIds];
                yield applyCleanupOnDependencyIds(deletionIds);
            }
            // In case of update apply the event on every rules
            if (type === EVENT_TYPE_UPDATE) {
                const updateEvent = event;
                const internalId = updateEvent.data.extensions[STIX_EXT_OCTI].id;
                const previousPatch = updateEvent.context.reverse_patch;
                const previousStix = jsonpatch.applyPatch(structuredClone(data), previousPatch).newDocument;
                for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
                    const rule = rules[ruleIndex];
                    // TODO Improve filtering definition to rely on attribute values
                    const isPreviouslyMatched = isMatchRuleFilters(rule, previousStix);
                    const isCurrentMatched = isMatchRuleFilters(rule, data);
                    const impactDependencies = isAttributesImpactDependencies(rule, previousPatch);
                    // Rule doesn't match anymore, need to clean up
                    if (impactDependencies || (isPreviouslyMatched && !isCurrentMatched)) {
                        yield applyCleanupOnDependencyIds([internalId]);
                    }
                    // Rule match, need to apply
                    if (isCurrentMatched) {
                        yield rule.update(data, updateEvent);
                    }
                }
            }
            // In case of creation apply the event on every rules
            if (type === EVENT_TYPE_CREATE) {
                for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
                    const rule = rules[ruleIndex];
                    const isImpactedElement = isMatchRuleFilters(rule, data);
                    if (isImpactedElement) {
                        yield rule.insert(data);
                    }
                }
            }
        }
        catch (e) {
            yield handleRuleError(event, e);
        }
    }
});
export const rulesCleanHandler = (context, user, instances, rules, deletedDependencies = []) => __awaiter(void 0, void 0, void 0, function* () {
    for (let i = 0; i < instances.length; i += 1) {
        const instance = instances[i];
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
            const rule = rules[ruleIndex];
            try {
                const isElementCleanable = isNotEmptyField(instance[`${RULE_PREFIX}${rule.id}`]);
                if (isElementCleanable) {
                    const processingElement = yield storeLoadByIdWithRefs(context, RULE_MANAGER_USER, instance.internal_id);
                    // In case of "inference of inference", element can be recursively cleanup by the deletion system
                    if (processingElement) {
                        yield rule.clean(processingElement, deletedDependencies);
                    }
                }
            }
            catch (err) {
                if (err.name === ALREADY_DELETED_ERROR) {
                    logApp.warn(err);
                }
                else {
                    logApp.error(err, { manager: 'RULE_ENGINE' });
                }
            }
        }
    }
});
const ruleStreamHandler = (streamEvents, lastEventId) => __awaiter(void 0, void 0, void 0, function* () {
    const context = executionContext('rule_manager', RULE_MANAGER_USER);
    // Create list of events to process
    // Events must be in a compatible version and not inferences events
    // Inferences directly handle recursively by the manager
    const compatibleEvents = streamEvents.filter((event) => {
        var _a, _b;
        const eventVersion = parseInt((_b = (_a = event.data) === null || _a === void 0 ? void 0 : _a.version) !== null && _b !== void 0 ? _b : '0', 10);
        return eventVersion >= MIN_LIVE_STREAM_EVENT_VERSION;
    });
    if (compatibleEvents.length > 0) {
        const ruleEvents = compatibleEvents.map((e) => e.data);
        // Execute the events
        yield rulesApplyHandler(context, RULE_MANAGER_USER, ruleEvents);
    }
    // Save the last processed event
    logApp.debug(`[OPENCTI] Rule manager saving state to ${lastEventId}`);
    yield patchAttribute(context, RULE_MANAGER_USER, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, { lastEventId });
});
const getInitRuleManager = () => __awaiter(void 0, void 0, void 0, function* () {
    const context = executionContext('rule_manager', RULE_MANAGER_USER);
    const ruleSettingsInput = { internal_id: RULE_ENGINE_ID, errors: [] };
    const created = yield createEntity(context, RULE_MANAGER_USER, ruleSettingsInput, ENTITY_TYPE_RULE_MANAGER);
    return created;
});
const initRuleManager = () => {
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
    const ruleHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([RULE_ENGINE_KEY], { retryCount: 0 });
            running = true;
            const ruleManager = yield getInitRuleManager();
            const { lastEventId } = ruleManager;
            logApp.info(`[OPENCTI-MODULE] Running rule manager from ${lastEventId !== null && lastEventId !== void 0 ? lastEventId : 'start'}`);
            // Start the stream listening
            const opts = { withInternal: true, streamName: REDIS_STREAM_NAME };
            streamProcessor = createStreamProcessor(RULE_MANAGER_USER, 'Rule manager', ruleStreamHandler, opts);
            yield streamProcessor.start(lastEventId);
            while (!shutdown && streamProcessor.running()) {
                lock.signal.throwIfAborted();
                yield wait(WAIT_TIME_ACTION);
            }
            logApp.info('[OPENCTI-MODULE] End of rule manager processing');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-MODULE] Rule engine already started by another API');
            }
            else {
                logApp.error(e, { manager: 'RULE_ENGINE' });
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
            scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield ruleHandler();
            }), SCHEDULE_TIME);
        }),
        status: () => {
            return {
                id: 'RULE_ENGINE',
                enable: booleanConf('rule_engine:enabled', false),
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping rule engine');
            shutdown = true;
            if (scheduler) {
                return clearIntervalAsync(scheduler);
            }
            return true;
        }),
    };
};
const ruleEngine = initRuleManager();
export const cleanRuleManager = (context, user, eventId) => __awaiter(void 0, void 0, void 0, function* () {
    const isRuleEngineActivated = yield isModuleActivated('RULE_ENGINE');
    // Clear the elastic status
    const patch = { lastEventId: eventId, errors: [] };
    const { element } = yield patchAttribute(context, user, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, patch);
    // Restart the manager
    yield ruleEngine.shutdown();
    yield ruleEngine.start();
    // Return the updated element
    return Object.assign({ activated: isRuleEngineActivated }, element);
});
export default ruleEngine;
