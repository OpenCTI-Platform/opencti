import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { logApp, TOPIC_PREFIX } from '../config/conf';
import { pubsub } from '../database/redis';
import { connectors } from '../database/repository';
import {
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_STATUS_TEMPLATE
} from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { UnsupportedError } from '../config/errors';
import type { BasicStoreEntity, BasicWorkflowStatusEntity, BasicWorkflowTemplateEntity } from '../types/store';
import { EntityOptions, listEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import type { AuthContext } from '../types/user';

let cache: any = {};

export const getEntitiesFromCache = async<T extends BasicStoreEntity>(context: AuthContext, type: string): Promise<Array<T>> => {
  let tracingSpan;
  try {
    if (context.tracing) {
      const tracer = context.tracing.getTracer();
      const ctx = context.tracing.getCtx();
      tracingSpan = tracer.startSpan(`CACHE ${type}`, {
        attributes: {
          [SemanticAttributes.DB_NAME]: 'cache_engine',
          [SemanticAttributes.DB_OPERATION]: 'select',
        },
        kind: 2 // Client
      }, ctx);
    }
    const fromCache = cache[type];
    if (!fromCache) {
      throw UnsupportedError(`${type} is not supported in cache configuration`);
    }
    if (!fromCache.values) {
      fromCache.values = await fromCache.fn();
    }
    if (tracingSpan) {
      tracingSpan.setStatus({ code: 1 });
      tracingSpan.end();
    }
    return fromCache.values;
  } catch (err) {
    if (tracingSpan) {
      tracingSpan.setStatus({ code: 2 });
      tracingSpan.end();
    }
    throw err;
  }
};

const workflowStatuses = async (context: AuthContext) => {
  const reloadStatuses = async () => {
    const templates = await listEntities<BasicWorkflowTemplateEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { connectionFormat: false });
    const args:EntityOptions<BasicWorkflowStatusEntity> = { orderBy: ['order'], orderMode: 'asc', connectionFormat: false };
    const statuses = await listEntities<BasicWorkflowStatusEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], args);
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
const platformRules = async (context: AuthContext) => {
  const reloadRules = async () => {
    return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_RULE], { connectionFormat: false });
  };
  return { values: await reloadRules(), fn: reloadRules };
};
const platformMarkings = async (context: AuthContext) => {
  const reloadMarkings = async () => {
    return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_MARKING_DEFINITION], { connectionFormat: false });
  };
  return { values: await reloadMarkings(), fn: reloadMarkings };
};

const initCacheManager = () => {
  let subscribeIdentifier: number;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Initializing cache manager');
      const context = executionContext('cache_manager');
      // Load initial data used for cache
      cache[ENTITY_TYPE_STATUS] = await workflowStatuses(context);
      cache[ENTITY_TYPE_CONNECTOR] = await platformConnectors(context);
      cache[ENTITY_TYPE_RULE] = await platformRules(context);
      cache[ENTITY_TYPE_MARKING_DEFINITION] = await platformMarkings(context);
      // Listen pub/sub configuration events
      // noinspection ES6MissingAwait
      subscribeIdentifier = await pubsub.subscribe(`${TOPIC_PREFIX}*`, (event) => {
        const { instance } = event;
        // Invalid cache if any entity has changed.
        if (cache[instance.entity_type]) {
          cache[instance.entity_type].values = undefined;
        } else {
          // This entity type is not part of the caching system
        }
      }, { pattern: true });
      logApp.info('[OPENCTI-MODULE] Cache manager initialized');
    },
    shutdown: async () => {
      if (subscribeIdentifier) {
        pubsub.unsubscribe(subscribeIdentifier);
      }
      cache = {};
      return true;
    }
  };
};
const cacheManager = initCacheManager();

export default cacheManager;
