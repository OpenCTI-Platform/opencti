import { filter, includes, map, pipe } from 'ramda';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER } from '../schema/internalObject';
import { BACKGROUND_TASK_QUEUES, connectorConfig } from './rabbitmq';
import { sinceNowInMinutes } from '../utils/format';
import { CONNECTOR_INTERNAL_ANALYSIS, CONNECTOR_INTERNAL_ENRICHMENT, CONNECTOR_INTERNAL_IMPORT_FILE, CONNECTOR_INTERNAL_NOTIFICATION } from '../schema/general';
import { fullEntitiesList, topEntitiesList, storeLoadById } from './middleware-loader';
import { isEmptyField, isNotEmptyField } from './utils';
import { BUILTIN_NOTIFIERS_CONNECTORS } from '../modules/notifier/notifier-statics';
import { builtInConnector, builtInConnectorsRuntime } from '../connector/connector-domain';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { shortHash } from '../schema/schemaUtils';
import { getSupportedContractsByImage } from '../modules/catalog/catalog-domain';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { getEntitiesMapFromCache } from './cache';
import { SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { ConnectorPriorityGroup } from '../generated/graphql';
import { injectProxyConfiguration } from '../config/proxy-config';

export const CONNECTOR_PRIORITY_GROUP_VALUES = Object.values(ConnectorPriorityGroup);

export const completeConnector = (connector) => {
  if (connector) {
    const completed = { ...connector };
    completed.title = connector.title ? connector.title : connector.name;
    completed.is_managed = isNotEmptyField(connector.catalog_id);
    completed.connector_scope = connector.connector_scope ? connector.connector_scope.split(',') : [];
    completed.config = connectorConfig(connector.id, connector.listen_callback_uri);
    completed.active = connector.built_in ? (connector.active ?? true) : (sinceNowInMinutes(connector.updated_at) < 5);
    return completed;
  }
  return null;
};

export const connector = async (context, user, id) => {
  // Database connector
  const element = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR)
    .then((conn) => completeConnector(conn));
  if (isEmptyField(element)) {
    // Built in connector
    const conn = await builtInConnector(context, user, id);
    return completeConnector(conn);
  }
  return element;
};

export const computeManagerConnectorContract = async (_context, _user, cn) => {
  const contracts = getSupportedContractsByImage();
  const contract = contracts.get(cn.manager_contract_image);
  return contract ? JSON.stringify(contract) : contract;
};

export const computeManagerConnectorExcerpt = async (_context, _user, cn) => {
  if (!cn.manager_contract_image) {
    return null;
  }

  const contracts = getSupportedContractsByImage();
  const contract = contracts.get(cn.manager_contract_image);

  if (!contract) {
    logApp.warn('No contract found for', { connectorName: cn.name });
    return null;
  }

  return {
    title: contract.title,
    slug: contract.slug
  };
};

export const computeManagerConnectorConfiguration = async (context, _user, cn, hideEncryptedConfigs = false) => {
  if (!cn.catalog_id) {
    return [];
  }
  const currentContractConfig = structuredClone(cn.manager_contract_configuration) ?? [];
  const fullContractConfig = hideEncryptedConfigs ? currentContractConfig.filter((c) => !c.encrypted) : currentContractConfig;
  const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  fullContractConfig.push({ key: 'CONNECTOR_ID', value: cn.internal_id });
  fullContractConfig.push({ key: 'CONNECTOR_NAME', value: cn.name });
  fullContractConfig.push({ key: 'CONNECTOR_TYPE', value: cn.connector_type });
  if (!hideEncryptedConfigs) {
    fullContractConfig.push({ key: 'OPENCTI_TOKEN', value: platformUsers.get(cn.connector_user_id)?.api_token });
  }

  // Inject proxy configuration dynamically
  const configWithProxy = injectProxyConfiguration(fullContractConfig);

  return configWithProxy.sort();
};

export const computeManagerConnectorImage = (cn) => {
  const contracts = getSupportedContractsByImage();
  const contract = contracts.get(cn.manager_contract_image);
  if (!contract) return '';
  return isNotEmptyField(cn.manager_contract_image) ? `${cn.manager_contract_image}:${contract.container_version}` : null;
};

export const computeManagerContractHash = async (context, user, cn) => {
  const image = computeManagerConnectorImage(cn);
  const config = await computeManagerConnectorConfiguration(context, user, cn);
  const subHash = config.map((c) => `${c.key}|${c.value}`);
  return shortHash({ image, subHash, state: cn.connector_state_timestamp });
};

export const connectors = async (context, user) => {
  const elements = await topEntitiesList(context, user, [ENTITY_TYPE_CONNECTOR]);
  const builtInElements = await builtInConnectorsRuntime(context, user);
  return map((conn) => completeConnector(conn), [...elements, ...builtInElements]);
};

export const connectorManager = async (context, user, managerId) => {
  return storeLoadById(context, user, managerId, ENTITY_TYPE_CONNECTOR_MANAGER);
};

export const connectorManagers = async (context, user) => {
  return fullEntitiesList(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
};

export const connectorsForManagers = async (context, user) => {
  const args = {
    filters: {
      mode: 'and',
      filters: [{ key: 'catalog_id', values: ['EXISTS'] }],
      filterGroups: [],
    },
    noFiltersChecking: true
  };
  const elements = await topEntitiesList(context, user, [ENTITY_TYPE_CONNECTOR], args);
  return elements.map((conn) => completeConnector(conn));
};

export const connectorsForWorker = async (context, user) => {
  // Expose connectors
  const registeredConnectors = await connectors(context, user);
  // region RETRO COMPATIBILITY Register internal queues
  /** @deprecated [>=6.3 & <6.6]. Remove and add migration to remove the queues. */
  registeredConnectors.push({
    id: 'sync',
    name: '[DEPRECATED] Internal sync manager',
    connector_scope: [],
    config: connectorConfig('sync'),
    active: true
  });
  registeredConnectors.push({
    id: 'playbook',
    name: '[DEPRECATED] Internal playbook manager',
    connector_scope: [],
    config: connectorConfig('playbook'),
    active: true
  });
  // endregion
  // Expose syncs
  const syncs = await fullEntitiesList(context, user, [ENTITY_TYPE_SYNC]);
  for (let i = 0; i < syncs.length; i += 1) {
    const sync = syncs[i];
    registeredConnectors.push({
      id: sync.internal_id,
      name: `Sync ${sync.internal_id} queue`,
      connector_scope: [],
      config: connectorConfig(sync.internal_id),
      active: true
    });
  }
  // Expose playbooks
  const playbooks = await fullEntitiesList(context, user, [ENTITY_TYPE_PLAYBOOK]);
  for (let i = 0; i < playbooks.length; i += 1) {
    const playbook = playbooks[i];
    registeredConnectors.push({
      id: playbook.internal_id,
      name: `Playbook ${playbook.internal_id} queue`,
      connector_scope: [],
      config: connectorConfig(playbook.internal_id),
      active: true
    });
  }
  // Expose background task queues
  for (let i = 0; i < BACKGROUND_TASK_QUEUES; i += 1) {
    registeredConnectors.push({
      id: `background-task-${i}`,
      name: `Background task ${i} queue`,
      connector_scope: [],
      config: connectorConfig(`background-task-${i}`),
      active: true
    });
  }
  // Expose pirs
  const pirs = await fullEntitiesList(context, user, [ENTITY_TYPE_PIR]);
  for (let i = 0; i < pirs.length; i += 1) {
    const pir = pirs[i];
    registeredConnectors.push({
      id: pir.internal_id,
      name: `Pir ${pir.internal_id} queue`,
      connector_scope: [],
      config: connectorConfig(pir.internal_id),
      active: true
    });
  }
  return registeredConnectors;
};

export const connectorsForPlaybook = async (context, user) => {
  const registeredConnectors = await connectors(context, user);
  return registeredConnectors.filter((r) => r.playbook_compatible === true);
};

const filterConnectors = (instances, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
    filter((c) => (onlyAuto ? c.auto === true : true)),
    filter((c) => (onlyContextual ? c.only_contextual === true : true)),
    filter((c) => (scope && c.connector_scope && c.connector_scope.length > 0
      ? includes(scope.toLowerCase(), map((s) => s.toLowerCase(), c.connector_scope))
      : true))
  )(instances);
};

export const connectorsFor = async (context, user, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const connects = await connectors(context, user);
  return filterConnectors(connects, type, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForEnrichment = async (context, user, scope, onlyAlive = false, onlyAuto = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsEnrichment = (instances, scope, onlyAlive = false, onlyAuto = false) => {
  return filterConnectors(instances, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsForImport = async (context, user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForAnalysis = async (context, user, scope = null, onlyAlive = true, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_ANALYSIS, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForNotification = async (context, user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const notificationConnectors = await connectorsFor(context, user, CONNECTOR_INTERNAL_NOTIFICATION, scope, onlyAlive, onlyAuto, onlyContextual);
  return [...notificationConnectors, ...Object.values(BUILTIN_NOTIFIERS_CONNECTORS)];
};
