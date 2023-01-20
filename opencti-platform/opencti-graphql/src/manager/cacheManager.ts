import * as R from 'ramda';
import { Promise as Bluebird } from 'bluebird';
import { logApp, TOPIC_PREFIX } from '../config/conf';
import { pubsub } from '../database/redis';
import { connectors as findConnectors } from '../database/repository';
import {
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_USER
} from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type {
  BasicStreamEntity,
  BasicTriggerEntity,
  BasicWorkflowStatusEntity,
  BasicWorkflowTemplateEntity
} from '../types/store';
import { EntityOptions, internalFindByIds, listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { resetCacheForEntity, writeCacheForEntity } from '../database/cache';
import type { AuthContext } from '../types/user';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { OrderingMode } from '../generated/graphql';
import { extractFilterIdsToResolve } from '../utils/filtering';
import { BasicStoreEntityTrigger, ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ES_MAX_CONCURRENCY } from '../database/engine';
import { resolveUserById } from '../domain/user';

const workflowStatuses = async (context: AuthContext) => {
  const reloadStatuses = async () => {
    const templates = await listAllEntities<BasicWorkflowTemplateEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { connectionFormat: false });
    const args:EntityOptions<BasicWorkflowStatusEntity> = { orderBy: ['order'], orderMode: OrderingMode.Asc, connectionFormat: false };
    const statuses = await listAllEntities<BasicWorkflowStatusEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], args);
    return statuses.map((status) => {
      const template = templates.find((t) => t.internal_id === status.template_id);
      return { ...status, name: template?.name ?? 'Error with template association' };
    });
  };
  return { values: await reloadStatuses(), fn: reloadStatuses };
};
const platformResolvedFilters = async (context: AuthContext) => {
  const reloadFilters = async () => {
    const filteringIds = [];
    const streams = await listAllEntities<BasicStreamEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
    filteringIds.push(...streams.map((s) => extractFilterIdsToResolve(JSON.parse(s.filters ?? '{}'))).flat());
    const triggers = await listAllEntities<BasicTriggerEntity>(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
    filteringIds.push(...triggers.map((s) => extractFilterIdsToResolve(JSON.parse(s.filters ?? '{}'))).flat());
    if (filteringIds.length > 0) {
      const resolvingIds = R.uniq(filteringIds);
      const loadedDependencies = await internalFindByIds(context, SYSTEM_USER, resolvingIds);
      return loadedDependencies.map((l) => ({ internal_id: l.internal_id, standard_id: l.standard_id }));
    }
    return [];
  };
  return { values: await reloadFilters(), fn: reloadFilters };
};
const platformConnectors = async (context: AuthContext) => {
  const reloadConnectors = async () => {
    return findConnectors(context, SYSTEM_USER);
  };
  return { values: await reloadConnectors(), fn: reloadConnectors };
};
const platformOrganizations = async (context: AuthContext) => {
  const reloadOrganizations = async () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_ORGANIZATION], { connectionFormat: false });
  };
  return { values: await reloadOrganizations(), fn: reloadOrganizations };
};
const platformRules = async (context: AuthContext) => {
  const reloadRules = async () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_RULE], { connectionFormat: false });
  };
  return { values: await reloadRules(), fn: reloadRules };
};
const platformMarkings = async (context: AuthContext) => {
  const reloadMarkings = async () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_MARKING_DEFINITION], { connectionFormat: false });
  };
  return { values: await reloadMarkings(), fn: reloadMarkings };
};
const platformTriggers = async (context: AuthContext) => {
  const reloadTriggers = async () => {
    return listAllEntities<BasicStoreEntityTrigger>(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
  };
  return { values: await reloadTriggers(), fn: reloadTriggers };
};
const platformUsers = async (context: AuthContext) => {
  const reloadUsers = async () => {
    const users = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], { connectionFormat: false });
    const allUserIds = users.map((user) => user.internal_id);
    return Bluebird.map(allUserIds, (userId: string) => resolveUserById(context, userId), { concurrency: ES_MAX_CONCURRENCY });
  };
  return { values: await reloadUsers(), fn: reloadUsers };
};
const platformSettings = async (context: AuthContext) => {
  const reloadSettings = async () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS], { connectionFormat: false });
  };
  return { values: await reloadSettings(), fn: reloadSettings };
};
const platformEntitySettings = async (context: AuthContext) => {
  const reloadEntitySettings = async () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  };
  return { values: await reloadEntitySettings(), fn: reloadEntitySettings };
};

const initCacheManager = () => {
  let subscribeIdentifier: number;
  return {
    start: async () => {
      const start = new Date().getTime();
      logApp.info('[OPENCTI-MODULE] Initializing cache manager');
      const context = executionContext('cache_manager');
      // Load initial data used for cache
      // First load the platform settings
      const [settings, entitySettings] = await Promise.all([platformSettings(context), platformEntitySettings(context)]);
      writeCacheForEntity(ENTITY_TYPE_SETTINGS, settings);
      writeCacheForEntity(ENTITY_TYPE_ENTITY_SETTING, entitySettings);
      // Then load the other parts
      const [users, markings, statuses, connectors, rules, organizations, triggers, filters] = await Promise.all([
        platformUsers(context),
        platformMarkings(context),
        workflowStatuses(context),
        platformConnectors(context),
        platformRules(context),
        platformOrganizations(context),
        platformTriggers(context),
        platformResolvedFilters(context),
      ]);
      writeCacheForEntity(ENTITY_TYPE_MARKING_DEFINITION, markings);
      writeCacheForEntity(ENTITY_TYPE_USER, users);
      writeCacheForEntity(ENTITY_TYPE_STATUS, statuses);
      writeCacheForEntity(ENTITY_TYPE_CONNECTOR, connectors);
      writeCacheForEntity(ENTITY_TYPE_TRIGGER, triggers);
      writeCacheForEntity(ENTITY_TYPE_RULE, rules);
      writeCacheForEntity(ENTITY_TYPE_IDENTITY_ORGANIZATION, organizations);
      writeCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS, filters);
      // Listen pub/sub configuration events
      // noinspection ES6MissingAwait
      subscribeIdentifier = await pubsub.subscribe(`${TOPIC_PREFIX}*`, (event) => {
        const { instance } = event;
        // Invalid cache if any entity has changed.
        resetCacheForEntity(instance.entity_type);
      }, { pattern: true });
      const startingDuration = Math.round((new Date().getTime() - start) / 1000);
      logApp.info(`[OPENCTI-MODULE] Cache manager initialized in ${startingDuration} sec(s)`);
    },
    shutdown: async () => {
      if (subscribeIdentifier) {
        pubsub.unsubscribe(subscribeIdentifier);
      }
      return true;
    }
  };
};
const cacheManager = initCacheManager();

export default cacheManager;
