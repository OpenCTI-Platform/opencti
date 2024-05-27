import { Promise as Bluebird } from 'bluebird';
import * as R from 'ramda';
import { logApp, TOPIC_PREFIX } from '../config/conf';
import { dynamicCacheUpdater, resetCacheForEntity, writeCacheForEntity } from '../database/cache';
import type { AuthContext } from '../types/user';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { FilterMode, OrderingMode } from '../generated/graphql';
import { extractFilterGroupValuesToResolveForCache } from '../utils/filtering/filtering-resolution';
import { type BasicStoreEntityTrigger, ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ES_MAX_CONCURRENCY } from '../database/engine';
import { stixLoadByIds } from '../database/middleware';
import { type EntityOptions, listAllEntities, listAllRelations } from '../database/middleware-loader';
import { pubSubSubscription } from '../database/redis';
import { connectors as findConnectors } from '../database/repository';
import type { BasicStoreEntityConnector } from '../connector/connector';
import { resolveUserById } from '../domain/user';
import { STATIC_NOTIFIERS } from '../modules/notifier/notifier-statics';
import type { BasicStoreEntityNotifier } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import {
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_USER
} from '../schema/internalObject';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import type { BasicStoreSettings } from '../types/settings';
import type { StixObject } from '../types/stix-common';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { BasicStoreRelation, BasicStreamEntity, BasicTriggerEntity, BasicWorkflowStatusEntity, BasicWorkflowTemplateEntity, StoreEntity, StoreRelation } from '../types/store';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import type { BasicStoreEntityPlaybook, ComponentDefinition } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { fromBase64, isNotEmptyField } from '../database/utils';
import { findAllPlaybooks } from '../modules/playbook/playbook-domain';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from '../modules/publicDashboard/publicDashboard-types';
import { getAllowedMarkings } from '../modules/publicDashboard/publicDashboard-domain';

const workflowStatuses = (context: AuthContext) => {
  const reloadStatuses = async () => {
    const templates = await listAllEntities<BasicWorkflowTemplateEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS_TEMPLATE], { connectionFormat: false });
    const args: EntityOptions<BasicWorkflowStatusEntity> = { orderBy: ['order'], orderMode: OrderingMode.Asc, connectionFormat: false };
    const statuses = await listAllEntities<BasicWorkflowStatusEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], args);
    return statuses.map((status) => {
      const template = templates.find((t) => t.internal_id === status.template_id);
      return { ...status, name: template?.name ?? 'Error with template association', template };
    });
  };
  return { values: null, fn: reloadStatuses };
};
const platformResolvedFilters = (context: AuthContext) => {
  const reloadFilters = async () => {
    const filteringIds = [];
    const initialFilterGroup = JSON.stringify({
      mode: 'and',
      filters: [],
      filterGroups: [],
    });
    // Stream filters
    const streams = await listAllEntities<BasicStreamEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
    filteringIds.push(...streams.map((s) => extractFilterGroupValuesToResolveForCache(JSON.parse(s.filters ?? initialFilterGroup))).flat());
    // Trigger filters
    const triggers = await listAllEntities<BasicTriggerEntity>(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
    filteringIds.push(...triggers.map((s) => extractFilterGroupValuesToResolveForCache(JSON.parse(s.filters ?? initialFilterGroup))).flat());
    // Connectors filters (for enrichment connectors)
    const connectors = await listAllEntities<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false });
    filteringIds.push(...connectors.map((s) => {
      const connFilters = s.connector_trigger_filters?.length > 0 ? s.connector_trigger_filters : initialFilterGroup;
      return extractFilterGroupValuesToResolveForCache(JSON.parse(connFilters));
    }).flat());
    // Playbook filters
    const playbooks = await listAllEntities<BasicStoreEntityPlaybook>(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK], { connectionFormat: false });
    const playbookFilterIds = playbooks
      .map((p) => JSON.parse(p.playbook_definition) as ComponentDefinition)
      .map((c) => c.nodes.map((n) => JSON.parse(n.configuration))).flat()
      .map((config) => config.filters)
      .filter((f) => isNotEmptyField(f))
      .map((f) => extractFilterGroupValuesToResolveForCache(JSON.parse(f)))
      .flat();
    filteringIds.push(...playbookFilterIds);
    // Resolve filteringIds
    if (filteringIds.length > 0) {
      const resolvingIds = R.uniq(filteringIds);
      const loadedDependencies = await stixLoadByIds(context, SYSTEM_USER, resolvingIds);
      return new Map(loadedDependencies.map((l: StixObject) => [l.extensions[STIX_EXT_OCTI].id, l]));
    }
    return new Map();
  };
  return { values: null, fn: reloadFilters };
};
const platformConnectors = (context: AuthContext) => {
  const reloadConnectors = () => {
    return findConnectors(context, SYSTEM_USER);
  };
  return { values: null, fn: reloadConnectors };
};
const platformOrganizations = (context: AuthContext) => {
  const reloadOrganizations = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_ORGANIZATION], { connectionFormat: false });
  };
  return { values: null, fn: reloadOrganizations };
};
const platformRules = (context: AuthContext) => {
  const reloadRules = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_RULE], { connectionFormat: false });
  };
  return { values: null, fn: reloadRules };
};
const platformDecayRules = (context: AuthContext) => {
  const reloadDecayRules = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_DECAY_RULE], { connectionFormat: false });
  };
  return { values: null, fn: reloadDecayRules };
};
const platformMarkings = (context: AuthContext) => {
  const reloadMarkings = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_MARKING_DEFINITION], { connectionFormat: false });
  };
  return { values: null, fn: reloadMarkings };
};
const platformTriggers = (context: AuthContext) => {
  const reloadTriggers = () => {
    return listAllEntities<BasicStoreEntityTrigger>(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
  };
  return { values: null, fn: reloadTriggers };
};
const platformRunningPlaybooks = (context: AuthContext) => {
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
const platformUsers = (context: AuthContext) => {
  const reloadUsers = async () => {
    const users = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], { connectionFormat: false });
    const allUserIds = users.map((user) => user.internal_id);
    return Bluebird.map(allUserIds, (userId: string) => resolveUserById(context, userId), { concurrency: ES_MAX_CONCURRENCY });
  };
  return { values: null, fn: reloadUsers };
};
const platformSettings = (context: AuthContext) => {
  const reloadSettings = async () => {
    const memberOfRelations = await listAllRelations<BasicStoreRelation>(context, SYSTEM_USER, [RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO], { connectionFormat: false });
    const memberOfGroups = memberOfRelations.filter((m) => m.entity_type === RELATION_MEMBER_OF)
      .map((mr) => ({ group: mr.toId, user: mr.fromId }));
    const membersGroupMap = new Map(Object.entries(R.groupBy((r) => r.group, memberOfGroups)).map(([k, v]) => [k, (v || []).map((t) => t.user)]));
    const memberOfOrgs = memberOfRelations.filter((m) => m.entity_type === RELATION_PARTICIPATE_TO)
      .map((mr) => ({ organization: mr.toId, user: mr.fromId }));
    const membersOrganizationMap = new Map(Object.entries(R.groupBy((r) => r.organization, memberOfOrgs)).map(([k, v]) => [k, (v || []).map((t) => t.user)]));
    return listAllEntities<BasicStoreSettings>(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS], { connectionFormat: false }).then((settings) => {
      return settings.map((s) => {
        const auditListenerIds = s.activity_listeners_ids ?? [];
        const activity_listeners_users = auditListenerIds.map((id: string) => membersGroupMap.get(id) ?? membersOrganizationMap.get(id) ?? [id]).flat();
        return { ...s, activity_listeners_users };
      });
    });
  };
  return { values: null, fn: reloadSettings };
};
const platformEntitySettings = (context: AuthContext) => {
  const reloadEntitySettings = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  };
  return { values: null, fn: reloadEntitySettings };
};
const platformManagerConfigurations = (context: AuthContext) => {
  const reloadManagerConfigurations = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_MANAGER_CONFIGURATION], { connectionFormat: false });
  };
  return { values: null, fn: reloadManagerConfigurations };
};
const platformStreams = (context: AuthContext) => {
  const reloadStreams = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
  };
  return { values: null, fn: reloadStreams };
};
const platformNotifiers = (context: AuthContext) => {
  const reloadNotifiers = async () => {
    const notifiers = await listAllEntities<BasicStoreEntityNotifier>(context, SYSTEM_USER, [ENTITY_TYPE_NOTIFIER], { connectionFormat: false });
    return [...notifiers, ...STATIC_NOTIFIERS].sort();
  };
  return { values: null, fn: reloadNotifiers };
};
const platformPublicDashboards = (context: AuthContext) => {
  const reloadPublicDashboards = async () => {
    const publicDashboards = await listAllEntities<BasicStoreEntityPublicDashboard>(context, SYSTEM_USER, [ENTITY_TYPE_PUBLIC_DASHBOARD], { connectionFormat: false });
    const publicDashboardsForCache: PublicDashboardCached[] = [];
    for (let i = 0; i < publicDashboards.length; i += 1) {
      const dash = publicDashboards[i];
      const markings = await getAllowedMarkings(context, SYSTEM_USER, dash);
      publicDashboardsForCache.push(
        {
          id: dash.id,
          enabled: dash.enabled,
          internal_id: dash.internal_id,
          uri_key: dash.uri_key,
          dashboard_id: dash.dashboard_id,
          private_manifest: JSON.parse(fromBase64(dash.private_manifest) ?? ''),
          user_id: dash.user_id,
          allowed_markings_ids: dash.allowed_markings_ids,
          allowed_markings: markings,
        }
      );
    }
    return publicDashboardsForCache;
  };
  return { values: null, fn: reloadPublicDashboards };
};

const initCacheManager = () => {
  let subscribeIdentifier: { topic: string; unsubscribe: () => void; };
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
    writeCacheForEntity(ENTITY_TYPE_DECAY_RULE, platformDecayRules(context));
    writeCacheForEntity(ENTITY_TYPE_IDENTITY_ORGANIZATION, platformOrganizations(context));
    writeCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS, platformResolvedFilters(context));
    writeCacheForEntity(ENTITY_TYPE_STREAM_COLLECTION, platformStreams(context));
    writeCacheForEntity(ENTITY_TYPE_NOTIFIER, platformNotifiers(context));
    writeCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD, platformPublicDashboards(context));
  };
  const resetCacheContent = async (event: { instance: StoreEntity | StoreRelation }) => {
    const { instance } = event;
    // Invalid cache if any entity has changed.
    resetCacheForEntity(instance.entity_type);
    // Smart dynamic cache loading (for filtering ...)
    dynamicCacheUpdater(instance);
  };
  return {
    init: () => initCacheContent(), // Use for testing
    start: async () => {
      initCacheContent();
      // Listen pub/sub configuration events
      subscribeIdentifier = await pubSubSubscription<{ instance: StoreEntity | StoreRelation }>(`${TOPIC_PREFIX}*`, async (event) => {
        await resetCacheContent(event);
      });
      logApp.info('[OPENCTI-MODULE] Cache manager pub sub listener initialized');
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping cache manager');
      if (subscribeIdentifier) {
        try {
          subscribeIdentifier.unsubscribe();
        } catch { /* dont care */
        }
      }
      return true;
    }
  };
};
const cacheManager = initCacheManager();

export default cacheManager;
