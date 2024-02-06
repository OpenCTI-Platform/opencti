var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Promise as Bluebird } from 'bluebird';
import * as R from 'ramda';
import { logApp, TOPIC_PREFIX } from '../config/conf';
import { dynamicCacheUpdater, resetCacheForEntity, writeCacheForEntity } from '../database/cache';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { FilterMode, OrderingMode } from '../generated/graphql';
import { extractFilterGroupValuesToResolveForCache } from '../utils/filtering/filtering-resolution';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ES_MAX_CONCURRENCY } from '../database/engine';
import { stixLoadByIds } from '../database/middleware';
import { listAllEntities, listAllRelations } from '../database/middleware-loader';
import { pubSubSubscription } from '../database/redis';
import { connectors as findConnectors } from '../database/repository';
import { resolveUserById } from '../domain/user';
import { STATIC_NOTIFIERS } from '../modules/notifier/notifier-statics';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_RULE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE, ENTITY_TYPE_STREAM_COLLECTION, ENTITY_TYPE_USER } from '../schema/internalObject';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { isNotEmptyField } from '../database/utils';
import { findAllPlaybooks } from '../modules/playbook/playbook-domain';
const workflowStatuses = (context) => {
    const reloadStatuses = () => __awaiter(void 0, void 0, void 0, function* () {
        const templates = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { connectionFormat: false });
        const args = { orderBy: ['order'], orderMode: OrderingMode.Asc, connectionFormat: false };
        const statuses = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], args);
        return statuses.map((status) => {
            var _a;
            const template = templates.find((t) => t.internal_id === status.template_id);
            return Object.assign(Object.assign({}, status), { name: (_a = template === null || template === void 0 ? void 0 : template.name) !== null && _a !== void 0 ? _a : 'Error with template association' });
        });
    });
    return { values: null, fn: reloadStatuses };
};
const platformResolvedFilters = (context) => {
    const reloadFilters = () => __awaiter(void 0, void 0, void 0, function* () {
        const filteringIds = [];
        const initialFilterGroup = JSON.stringify({
            mode: 'and',
            filters: [],
            filterGroups: [],
        });
        // Stream filters
        const streams = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
        filteringIds.push(...streams.map((s) => { var _a; return extractFilterGroupValuesToResolveForCache(JSON.parse((_a = s.filters) !== null && _a !== void 0 ? _a : initialFilterGroup)); }).flat());
        // Trigger filters
        const triggers = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
        filteringIds.push(...triggers.map((s) => { var _a; return extractFilterGroupValuesToResolveForCache(JSON.parse((_a = s.filters) !== null && _a !== void 0 ? _a : initialFilterGroup)); }).flat());
        // Playbook filters
        const playbooks = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK], { connectionFormat: false });
        const playbookFilterIds = playbooks
            .map((p) => JSON.parse(p.playbook_definition))
            .map((c) => c.nodes.map((n) => JSON.parse(n.configuration))).flat()
            .map((config) => config.filters)
            .filter((f) => isNotEmptyField(f))
            .map((f) => extractFilterGroupValuesToResolveForCache(JSON.parse(f)))
            .flat();
        filteringIds.push(...playbookFilterIds);
        // Resolve filteringIds
        if (filteringIds.length > 0) {
            const resolvingIds = R.uniq(filteringIds);
            const loadedDependencies = yield stixLoadByIds(context, SYSTEM_USER, resolvingIds);
            return new Map(loadedDependencies.map((l) => [l.extensions[STIX_EXT_OCTI].id, l]));
        }
        return new Map();
    });
    return { values: null, fn: reloadFilters };
};
const platformConnectors = (context) => {
    const reloadConnectors = () => {
        return findConnectors(context, SYSTEM_USER);
    };
    return { values: null, fn: reloadConnectors };
};
const platformOrganizations = (context) => {
    const reloadOrganizations = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_ORGANIZATION], { connectionFormat: false });
    };
    return { values: null, fn: reloadOrganizations };
};
const platformRules = (context) => {
    const reloadRules = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_RULE], { connectionFormat: false });
    };
    return { values: null, fn: reloadRules };
};
const platformMarkings = (context) => {
    const reloadMarkings = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_MARKING_DEFINITION], { connectionFormat: false });
    };
    return { values: null, fn: reloadMarkings };
};
const platformTriggers = (context) => {
    const reloadTriggers = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
    };
    return { values: null, fn: reloadTriggers };
};
const platformRunningPlaybooks = (context) => {
    const reloadPlaybooks = () => {
        const filters = {
            mode: FilterMode.And,
            filters: [{ key: ['playbook_running'], values: ['true'] }],
            filterGroups: [],
        };
        const opts = { filters, noFiltersChecking: true, connectionFormat: false };
        return findAllPlaybooks(context, SYSTEM_USER, opts);
    };
    return { values: null, fn: reloadPlaybooks };
};
const platformUsers = (context) => {
    const reloadUsers = () => __awaiter(void 0, void 0, void 0, function* () {
        const users = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], { connectionFormat: false });
        const allUserIds = users.map((user) => user.internal_id);
        return Bluebird.map(allUserIds, (userId) => resolveUserById(context, userId), { concurrency: ES_MAX_CONCURRENCY });
    });
    return { values: null, fn: reloadUsers };
};
const platformSettings = (context) => {
    const reloadSettings = () => __awaiter(void 0, void 0, void 0, function* () {
        const memberOfRelations = yield listAllRelations(context, SYSTEM_USER, [RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO], { connectionFormat: false });
        const memberOfGroups = memberOfRelations.filter((m) => m.entity_type === RELATION_MEMBER_OF)
            .map((mr) => ({ group: mr.toId, user: mr.fromId }));
        const membersGroupMap = new Map(Object.entries(R.groupBy((r) => r.group, memberOfGroups)).map(([k, v]) => [k, (v || []).map((t) => t.user)]));
        const memberOfOrgs = memberOfRelations.filter((m) => m.entity_type === RELATION_PARTICIPATE_TO)
            .map((mr) => ({ organization: mr.toId, user: mr.fromId }));
        const membersOrganizationMap = new Map(Object.entries(R.groupBy((r) => r.organization, memberOfOrgs)).map(([k, v]) => [k, (v || []).map((t) => t.user)]));
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS], { connectionFormat: false }).then((settings) => {
            return settings.map((s) => {
                var _a;
                const auditListenerIds = (_a = s.activity_listeners_ids) !== null && _a !== void 0 ? _a : [];
                const activity_listeners_users = auditListenerIds.map((id) => { var _a, _b; return (_b = (_a = membersGroupMap.get(id)) !== null && _a !== void 0 ? _a : membersOrganizationMap.get(id)) !== null && _b !== void 0 ? _b : [id]; }).flat();
                return Object.assign(Object.assign({}, s), { activity_listeners_users });
            });
        });
    });
    return { values: null, fn: reloadSettings };
};
const platformEntitySettings = (context) => {
    const reloadEntitySettings = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
    };
    return { values: null, fn: reloadEntitySettings };
};
const platformManagerConfigurations = (context) => {
    const reloadManagerConfigurations = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_MANAGER_CONFIGURATION], { connectionFormat: false });
    };
    return { values: null, fn: reloadManagerConfigurations };
};
const platformStreams = (context) => {
    const reloadStreams = () => {
        return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
    };
    return { values: null, fn: reloadStreams };
};
const platformNotifiers = (context) => {
    const reloadNotifiers = () => __awaiter(void 0, void 0, void 0, function* () {
        const notifiers = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_NOTIFIER], { connectionFormat: false });
        return [...notifiers, ...STATIC_NOTIFIERS].sort();
    });
    return { values: null, fn: reloadNotifiers };
};
const initCacheManager = () => {
    let subscribeIdentifier;
    const initCacheContent = () => {
        const context = executionContext('cache_manager');
        writeCacheForEntity(ENTITY_TYPE_SETTINGS, platformSettings(context));
        writeCacheForEntity(ENTITY_TYPE_ENTITY_SETTING, platformEntitySettings(context));
        writeCacheForEntity(ENTITY_TYPE_MANAGER_CONFIGURATION, platformManagerConfigurations(context));
        writeCacheForEntity(ENTITY_TYPE_MARKING_DEFINITION, platformMarkings(context));
        writeCacheForEntity(ENTITY_TYPE_USER, platformUsers(context));
        writeCacheForEntity(ENTITY_TYPE_STATUS, workflowStatuses(context));
        writeCacheForEntity(ENTITY_TYPE_CONNECTOR, platformConnectors(context));
        writeCacheForEntity(ENTITY_TYPE_TRIGGER, platformTriggers(context));
        writeCacheForEntity(ENTITY_TYPE_PLAYBOOK, platformRunningPlaybooks(context));
        writeCacheForEntity(ENTITY_TYPE_RULE, platformRules(context));
        writeCacheForEntity(ENTITY_TYPE_IDENTITY_ORGANIZATION, platformOrganizations(context));
        writeCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS, platformResolvedFilters(context));
        writeCacheForEntity(ENTITY_TYPE_STREAM_COLLECTION, platformStreams(context));
        writeCacheForEntity(ENTITY_TYPE_NOTIFIER, platformNotifiers(context));
    };
    const resetCacheContent = (event) => __awaiter(void 0, void 0, void 0, function* () {
        const { instance } = event;
        // Invalid cache if any entity has changed.
        resetCacheForEntity(instance.entity_type);
        // Smart dynamic cache loading (for filtering ...)
        dynamicCacheUpdater(instance);
    });
    return {
        init: () => initCacheContent(), // Use for testing
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            initCacheContent();
            // Listen pub/sub configuration events
            subscribeIdentifier = yield pubSubSubscription(`${TOPIC_PREFIX}*`, (event) => __awaiter(void 0, void 0, void 0, function* () {
                yield resetCacheContent(event);
            }));
            logApp.info('[OPENCTI-MODULE] Cache manager pub sub listener initialized');
        }),
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping cache manager');
            if (subscribeIdentifier) {
                try {
                    subscribeIdentifier.unsubscribe();
                }
                catch ( /* dont care */_a) { /* dont care */
                }
            }
            return true;
        })
    };
};
const cacheManager = initCacheManager();
export default cacheManager;
