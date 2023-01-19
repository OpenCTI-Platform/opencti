import { logApp, TOPIC_PREFIX } from '../config/conf';
import { pubsub } from '../database/redis';
import { connectors } from '../database/repository';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_RULE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { BasicWorkflowStatusEntity, BasicWorkflowTemplateEntity } from '../types/store';
import { EntityOptions, listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { resetCacheForEntity, writeCacheForEntity } from '../database/cache';
import type { AuthContext } from '../types/user';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../schema/stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

const workflowStatuses = async (context: AuthContext) => {
  const reloadStatuses = async () => {
    const templates = await listAllEntities<BasicWorkflowTemplateEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { connectionFormat: false });
    const args:EntityOptions<BasicWorkflowStatusEntity> = { orderBy: ['order'], orderMode: 'asc', connectionFormat: false };
    const statuses = await listAllEntities<BasicWorkflowStatusEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], args);
    return statuses.map((status) => {
      const template = templates.find((t) => t.internal_id === status.template_id);
      return { ...status, name: template?.name ?? 'Error with template association' };
    });
  };
  return { values: await reloadStatuses(), fn: reloadStatuses };
};
const platformConnectors = async (context: AuthContext) => {
  const reloadConnectors = async () => {
    return connectors(context, SYSTEM_USER);
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
      logApp.info('[OPENCTI-MODULE] Initializing cache manager');
      const context = executionContext('cache_manager');
      // Load initial data used for cache
      writeCacheForEntity(ENTITY_TYPE_STATUS, await workflowStatuses(context));
      writeCacheForEntity(ENTITY_TYPE_CONNECTOR, await platformConnectors(context));
      writeCacheForEntity(ENTITY_TYPE_RULE, await platformRules(context));
      writeCacheForEntity(ENTITY_TYPE_MARKING_DEFINITION, await platformMarkings(context));
      writeCacheForEntity(ENTITY_TYPE_SETTINGS, await platformSettings(context));
      writeCacheForEntity(ENTITY_TYPE_ENTITY_SETTING, await platformEntitySettings(context));
      writeCacheForEntity(ENTITY_TYPE_IDENTITY_ORGANIZATION, await platformOrganizations(context));
      // Listen pub/sub configuration events
      // noinspection ES6MissingAwait
      subscribeIdentifier = await pubsub.subscribe(`${TOPIC_PREFIX}*`, (event) => {
        const { instance } = event;
        // Invalid cache if any entity has changed.
        resetCacheForEntity(instance.entity_type);
      }, { pattern: true });
      logApp.info('[OPENCTI-MODULE] Cache manager initialized');
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
