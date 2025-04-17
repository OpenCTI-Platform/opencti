import * as R from 'ramda';
import { logApp, TOPIC_PREFIX } from '../config/conf';
import { addCacheForEntity, refreshCacheForEntity, removeCacheForEntity, writeCacheForEntity } from '../database/cache';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { FilterMode, OrderingMode } from '../generated/graphql';
import { extractFilterGroupValuesToResolveForCache } from '../utils/filtering/filtering-resolution';
import { type BasicStoreEntityTrigger, ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { stixLoadByIds } from '../database/middleware';
import { type EntityOptions, internalFindByIds, listAllEntities, listAllRelations } from '../database/middleware-loader';
import { pubSubSubscription } from '../database/redis';
import { connectors as findConnectors } from '../database/repository';
import { buildCompleteUsers, resolveUserById } from '../domain/user';
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
import type { StixObject } from '../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import type {
  BasicStoreCommon,
  BasicStoreRelation,
  BasicStreamEntity,
  BasicTriggerEntity,
  BasicWorkflowStatusEntity,
  BasicWorkflowTemplateEntity,
  StoreEntity,
  StoreRelation
} from '../types/store';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import type { BasicStoreEntityPlaybook, ComponentDefinition } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { fromBase64, isNotEmptyField } from '../database/utils';
import { findAllPlaybooks } from '../modules/playbook/playbook-domain';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from '../modules/publicDashboard/publicDashboard-types';
import { getAllowedMarkings } from '../modules/publicDashboard/publicDashboard-domain';
import type { BasicStoreEntityConnector } from '../types/connector';
import { getEnterpriseEditionInfoFromPem } from '../modules/settings/licensing';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { emptyFilterGroup } from '../utils/filtering/filtering-utils';
import { FunctionalError } from '../config/errors';

const ADDS_TOPIC = `${TOPIC_PREFIX}*ADDED_TOPIC`;
const EDITS_TOPIC = `${TOPIC_PREFIX}*EDIT_TOPIC`;
const DELETES_TOPIC = `${TOPIC_PREFIX}*DELETE_TOPIC`;

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
// extract the filters of the instance in case of resolved filters cache update
const extractResolvedFiltersFromInstance = (instance: BasicStoreCommon) => {
  const initialFilterGroup = JSON.stringify(emptyFilterGroup);
  const filteringIds = []; // will contain the ids that are in the instance filters values
  if (instance.entity_type === ENTITY_TYPE_STREAM_COLLECTION) {
    const streamFilterIds = extractFilterGroupValuesToResolveForCache(
      JSON.parse((instance as BasicStreamEntity).filters ?? initialFilterGroup)
    );
    filteringIds.push(...streamFilterIds);
  } else if (instance.entity_type === ENTITY_TYPE_TRIGGER) {
    const triggerFilterIds = extractFilterGroupValuesToResolveForCache(
      JSON.parse((instance as BasicTriggerEntity).filters ?? initialFilterGroup)
    );
    filteringIds.push(...triggerFilterIds);
  } else if (instance.entity_type === ENTITY_TYPE_CONNECTOR) {
    const connFilters = (instance as BasicStoreEntityConnector).connector_trigger_filters?.length > 0
      ? (instance as BasicStoreEntityConnector).connector_trigger_filters
      : initialFilterGroup;
    const connFilterIds = extractFilterGroupValuesToResolveForCache(JSON.parse(connFilters));
    filteringIds.push(...connFilterIds);
  } else if (instance.entity_type === ENTITY_TYPE_PLAYBOOK) {
    const playbookFilterIds = ((JSON.parse((instance as BasicStoreEntityPlaybook).playbook_definition)) as ComponentDefinition)
      .nodes.map((n) => JSON.parse(n.configuration))
      .map((config) => config.filters)
      .filter((f) => isNotEmptyField(f))
      .map((f) => extractFilterGroupValuesToResolveForCache(JSON.parse(f)))
      .flat();
    filteringIds.push(...playbookFilterIds);
  } else {
    throw FunctionalError('Resolved filters are only saved in cache for streams, triggers, connectors and playbooks, not for this entity type', { entity_type: instance.entity_type });
  }
  return filteringIds;
};
const platformResolvedFilters = (context: AuthContext) => {
  const reloadFilters = async () => {
    // Fetch streams, triggers, connectors (for enrichment connectors) and playbooks
    const streams = await listAllEntities<BasicStreamEntity>(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], { connectionFormat: false });
    const triggers = await listAllEntities<BasicTriggerEntity>(context, SYSTEM_USER, [ENTITY_TYPE_TRIGGER], { connectionFormat: false });
    const connectors = await listAllEntities<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false });
    const playbooks = await listAllEntities<BasicStoreEntityPlaybook>(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK], { connectionFormat: false });
    // Fetch the filters of those entities
    const filteringIds = [...streams, ...triggers, ...connectors, ...playbooks].map((s) => extractResolvedFiltersFromInstance(s)).flat();
    // Resolve the filters ids
    if (filteringIds.length > 0) {
      const resolvingIds = R.uniq(filteringIds);
      const loadedDependencies = await stixLoadByIds(context, SYSTEM_USER, resolvingIds);
      return new Map(loadedDependencies.map((l: StixObject) => [l.extensions[STIX_EXT_OCTI].id, l]));
    }
    return new Map();
  };
  const refreshFilter = async (values: Map<string, StixObject>, instance: BasicStoreCommon) => {
    const filteringIds = extractResolvedFiltersFromInstance(instance);
    // Resolve filters ids that are not already in the cache
    const currentFiltersValues = values; // current cache map
    const idsToSolve: string[] = []; // will contain the ids to resolve that are not already in the cache
    filteringIds.forEach((id) => {
      if (!currentFiltersValues.has(id)) {
        idsToSolve.push(id);
      }
    });
    const loadedDependencies = await stixLoadByIds(context, SYSTEM_USER, R.uniq(idsToSolve)); // fetch the stix instance of the ids
    // Add resolved stix entities to the cache map
    loadedDependencies.forEach((l: StixObject) => currentFiltersValues.set(l.extensions[STIX_EXT_OCTI].id, l));
    return currentFiltersValues;
  };
  return { values: null, fn: reloadFilters, refresh: refreshFilter };
};
const platformConnectors = (context: AuthContext) => {
  const reloadConnectors = () => {
    return findConnectors(context, SYSTEM_USER);
  };
  return { values: null, fn: reloadConnectors };
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
  const loadUsers = async (ids?: string[]): Promise<AuthUser[]> => {
    const users = ids ? await internalFindByIds(context, SYSTEM_USER, ids)
      : await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], { connectionFormat: false });
    return buildCompleteUsers(context, users);
  };
  const removeUser = async (values: AuthUser[], instance: BasicStoreCommon) => {
    return (values ?? []).filter((user) => user.internal_id !== instance.internal_id);
  };
  const refreshUsers = async (values: AuthUser[], instance: BasicStoreCommon | BasicStoreCommon[]) => {
    const users = Array.isArray(instance) ? instance : [instance];
    const userIds = users.map((u) => u.internal_id);
    const refreshValues = (values ?? []).filter((user) => !userIds.includes(user.internal_id));
    const reloadedUsers = await loadUsers(userIds);
    refreshValues.push(...reloadedUsers);
    return refreshValues;
  };
  const addUser = async (values: AuthUser[] | null, instance: BasicStoreCommon) => {
    if (values) { // If values not preloaded yet
      // If user already available (local mode), do not add it
      if (values.find((user) => user.internal_id === instance.internal_id)) {
        return values;
      }
      // If user not available (cluster mode)
      const user = await resolveUserById(context, instance.internal_id);
      values.push(user);
      return values;
    }
    return values;
  };
  return { values: null, fn: loadUsers, remove: removeUser, refresh: refreshUsers, add: addUser };
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
        const ee_info = getEnterpriseEditionInfoFromPem(s.internal_id, s.enterprise_license);
        const activity_listeners_users = auditListenerIds.map((id: string) => membersGroupMap.get(id) ?? membersOrganizationMap.get(id) ?? [id]).flat();
        return { ...s, valid_enterprise_edition: ee_info.license_validated, activity_listeners_users };
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
const platformDraftWorkspaces = (context: AuthContext) => {
  const reloadDraftWorkspaces = () => {
    return listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_DRAFT_WORKSPACE], { connectionFormat: false });
  };
  return { values: null, fn: reloadDraftWorkspaces };
};
type SubEvent = { instance: StoreEntity | StoreRelation };

const initCacheManager = () => {
  let subscribeAdd: { topic: string; unsubscribe: () => void; };
  let subscribeEdit: { topic: string; unsubscribe: () => void; };
  let subscribeDelete: { topic: string; unsubscribe: () => void; };
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
    writeCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS, platformResolvedFilters(context));
    writeCacheForEntity(ENTITY_TYPE_STREAM_COLLECTION, platformStreams(context));
    writeCacheForEntity(ENTITY_TYPE_NOTIFIER, platformNotifiers(context));
    writeCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD, platformPublicDashboards(context));
    writeCacheForEntity(ENTITY_TYPE_DRAFT_WORKSPACE, platformDraftWorkspaces(context));
  };
  return {
    init: () => initCacheContent(), // Use for testing
    start: async () => {
      initCacheContent();
      subscribeAdd = await pubSubSubscription<SubEvent>(ADDS_TOPIC, async (event) => {
        await addCacheForEntity(event.instance);
      });
      subscribeEdit = await pubSubSubscription<SubEvent>(EDITS_TOPIC, async (event) => {
        await refreshCacheForEntity(event.instance);
      });
      subscribeDelete = await pubSubSubscription<SubEvent>(DELETES_TOPIC, async (event) => {
        await removeCacheForEntity(event.instance);
      });
      logApp.info('[OPENCTI-MODULE] Cache manager pub sub listener initialized');
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping cache manager');
      try { subscribeAdd.unsubscribe(); } catch { /* dont care */ }
      try { subscribeEdit.unsubscribe(); } catch { /* dont care */ }
      try { subscribeDelete.unsubscribe(); } catch { /* dont care */ }
      return true;
    }
  };
};
const cacheManager = initCacheManager();

export default cacheManager;
