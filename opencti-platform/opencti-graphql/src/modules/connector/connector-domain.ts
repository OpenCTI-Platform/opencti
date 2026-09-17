import { createEntity, internalDeleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { now } from '../../utils/format';
import { isEmptyField } from '../../database/utils';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_EXPORT_FILE } from '../../schema/general';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../../utils/access';
import { notify } from '../../database/redis';
import {
  type ConnectorHealthMetrics,
  redisDeleteConnectorHeartbeat,
  redisGetConnectorHealthMetrics,
  redisGetConnectorHeartbeat,
  redisGetConnectorsHeartbeats,
  redisGetManagedConnectorAutoUpgradeStatus,
  redisSetConnectorHealthMetrics,
  redisSetConnectorHeartbeat,
  redisSetConnectorLogs,
  redisSetManagedConnectorAutoUpgradeStatus,
} from './connector-redis';
import semver from 'semver';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import {
  findCatalogContractsByImageName,
  findCatalogContractsBySlugs,
  findLatestCompatibleCatalogContractByImageName,
  findLatestCompatibleCatalogContractBySlug,
} from '../catalog/catalog-repository';
import { buildConnectorUpdateStatus, compareContractVersions, groupContractVersionsBySlug } from '../catalog/catalog-version-utils';
import { findManagedConnectorsByCatalogId } from './connector-repository';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityConnector, BasicStoreEntityConnectorManager, ConnectorInfo, StoreEntityConnector } from './connector-types';
import {
  type AddManagedConnectorInput,
  ConnectorPriorityGroup,
  type CurrentConnectorStatusInput,
  type EditInput,
  type EditManagedConnectorInput,
  type HealthConnectorStatusInput,
  type LogsConnectorStatusInput,
  type RegisterConnectorInput,
  type RegisterConnectorsManagerInput,
  type RequestConnectorStatusInput,
  type UpdateConnectorManagerStatusInput,
} from '../../generated/graphql';
import { BUS_TOPICS, logApp, PLATFORM_VERSION } from '../../config/conf';
import { deleteWorkForConnector } from '../../domain/work';
import { addConnectorDeployedCount } from '../../manager/telemetryManager';
import {
  computeConnectorTargetContract,
  encryptValue,
  mapContractEntityFieldsToEmbeddedConnectorManagerContract,
  mapContractEntityFieldsToGraphqlCatalogContract,
} from '../../modules/catalog/catalog-domain';
import { getEntitiesMapFromCache } from '../../database/cache';
import { createOnTheFlyUser } from '../../modules/user/user-domain';
import { filter, includes, map, pipe } from 'ramda';
import { BACKGROUND_TASK_QUEUES, connectorConfig, getConnectorQueueDetails, purgeConnectorQueues, registerConnectorQueues, unregisterConnector } from './connector-rabbitmq';
import { sinceNowInMinutes } from '../../utils/format';
import { CONNECTOR_INTERNAL_ANALYSIS, CONNECTOR_INTERNAL_ENRICHMENT, CONNECTOR_INTERNAL_IMPORT_FILE, CONNECTOR_INTERNAL_NOTIFICATION } from '../../schema/general';
import { isNotEmptyField } from '../../database/utils';
import { BUILTIN_NOTIFIERS_CONNECTORS } from '../notifier/notifier-statics';
import { builtInConnector, builtInConnectorsRuntime } from './connector-built-in-domain';
import { shortHash } from '../../schema/schemaUtils';
import { getPlatformCrypto } from '../../utils/platformCrypto';
import { SignJWT } from 'jose';
import { memoize } from '../../utils/memoize';
import { addUserTokenByAdmin, revokeUserTokenByAdmin } from '../user/user-domain';
import { getClientBase } from '../../database/redis';
import { lockResources } from '../../lock/master-lock';
import { LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { injectProxyConfiguration } from '../../config/proxy-config';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { ENTITY_TYPE_PLAYBOOK } from '../playbook/playbook-types';
import conf, { booleanConf, DECOUPLING_VERSIONS_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { findConnectorById, findConnectorManagerById, findConnectorManagers, findConnectors, findManagedConnectors } from './connector-repository';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';

const sanitizeContainerName = (label: string): string => {
  let sanitized = label
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .toLowerCase()
    .replace(/^-+/, '')
    .replace(/-+$/, '');

  if (sanitized.length > 63) {
    sanitized = sanitized.substring(0, 63);
    sanitized = sanitized.replace(/-+$/, '');
  }

  return sanitized.length === 0 ? `a-${Math.floor(Math.random() * 10)}` : sanitized;
};

const getJWTKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveEd25519KeyPair(['connector', 'http'], 1);
});

export const getConnectorJwks = async () => {
  const keyPair = await getJWTKeyPair();
  return JSON.stringify(keyPair.jwks);
};

export const issueConnectorJWT = async () => {
  const keyPair = await getJWTKeyPair();
  const jwt = new SignJWT({ iss: 'opencti', sub: 'connector' }).setIssuedAt().setExpirationTime('1h');
  return keyPair.signJwt(jwt);
};

// lastSeenAt is the last connector heartbeat (ping or registration), stored in Redis.
// Never derive it from updated_at: any write on the connector entity bumps it.
export const isConnectorActive = (connector: any, lastSeenAt?: string | null) => {
  if (connector.built_in) {
    return connector.active ?? true;
  }
  if (connector.is_managed || isNotEmptyField(connector.catalog_id)) {
    // return false if managed connector is stopped or stopping
    const connectorStopped = connector.manager_requested_status === 'stopping'
      || connector.manager_requested_status === 'stopped'
      || connector.manager_current_status === 'stopped';
    if (connectorStopped) {
      return false;
    }
  }
  return isNotEmptyField(lastSeenAt) && sinceNowInMinutes(lastSeenAt) < 5;
};

// Liveness is a single derived field: failing to read heartbeats must not fail the loading of connectors
// (workers configuration, connectors selection, cache...). Connectors are then considered inactive.
export const loadConnectorHeartbeat = async (connectorId: string) => {
  try {
    return await redisGetConnectorHeartbeat(connectorId);
  } catch (err) {
    logApp.warn('[OPENCTI-MODULE] Unable to read connector heartbeat, connector considered inactive', { cause: err, connectorId });
    return null;
  }
};

const loadConnectorsHeartbeats = async () => {
  try {
    return await redisGetConnectorsHeartbeats();
  } catch (err) {
    logApp.warn('[OPENCTI-MODULE] Unable to read connectors heartbeats, connectors considered inactive', { cause: err });
    return new Map<string, string>();
  }
};

export const completeConnector = (connector: any, lastSeenAt?: string | null) => {
  if (!connector) {
    return null;
  }
  const completed = { ...connector };
  completed.title = connector.title ? connector.title : connector.name;
  completed.is_managed = isNotEmptyField(connector.catalog_id);
  completed.connector_scope = Array.isArray(connector.connector_scope)
    ? connector.connector_scope
    : connector.connector_scope ? connector.connector_scope.split(',') : [];
  completed.config = connectorConfig(connector.id, connector.listen_callback_uri);
  // Built-in connectors do not send heartbeats
  completed.last_seen_at = connector.built_in ? null : (lastSeenAt ?? null);
  completed.active = isConnectorActive(connector, lastSeenAt);
  return completed;
};

export const connectors = async (context: AuthContext, user: AuthUser) => {
  const [storedConnectors, builtInConnectors] = await Promise.all([
    findConnectors(context, user),
    builtInConnectorsRuntime(context, user),
  ]);
  const heartbeats = await loadConnectorsHeartbeats();
  return [...storedConnectors, ...builtInConnectors].map((connector) => completeConnector(connector, heartbeats.get(connector.internal_id)));
};

export const connector = async (context: AuthContext, user: AuthUser, connectorId: string) => {
  const storedConnector = await findConnectorById(context, user, connectorId);
  if (storedConnector) {
    return completeConnector(storedConnector, await loadConnectorHeartbeat(storedConnector.internal_id));
  }
  return completeConnector(await builtInConnector(context, user, connectorId));
};

export const connectorManager = (context: AuthContext, user: AuthUser, managerId: string) => {
  return findConnectorManagerById(context, user, managerId);
};

export const connectorManagers = (context: AuthContext, user: AuthUser) => {
  return findConnectorManagers(context, user);
};

export const connectorsForManagers = async (context: AuthContext, user: AuthUser) => {
  const managedConnectors = await findManagedConnectors(context, user);
  const heartbeats = await loadConnectorsHeartbeats();
  return managedConnectors.map((connector) => completeConnector(connector, heartbeats.get(connector.internal_id)));
};

const NO_UPDATE_STATUS = {
  update_available: false,
  latest_compatible_version: null,
  has_newer_incompatible_version: false,
};

// Batched for connector lists: the catalog contracts of all the connectors are loaded at once, by slug.
// Catalog keyword fields are matched case insensitively, so the contracts are grouped the same way.
// A catalog failure only removes the update hints: the connectors themselves still resolve.
export const computeConnectorsUpdateStatus = async (context: AuthContext, user: AuthUser, connectorsToCheck: any[]) => {
  // Without decoupled versions, the catalog only changes with the platform: no update to report
  if (!isFeatureEnabled(DECOUPLING_VERSIONS_FEATURE_FLAG)) {
    return connectorsToCheck.map(() => NO_UPDATE_STATUS);
  }
  try {
    const slugs = connectorsToCheck.map((cn) => cn?.manager_contract?.slug?.toLowerCase() ?? null);
    const uniqueSlugs = [...new Set(slugs.filter(isNotEmptyField))];
    const contracts = uniqueSlugs.length > 0 ? await findCatalogContractsBySlugs(context, user, uniqueSlugs) : [];
    const versionsBySlug = groupContractVersionsBySlug(contracts, (contract) => contract.slug.toLowerCase());
    return connectorsToCheck.map((cn, index) => {
      const slug = slugs[index];
      if (!slug) {
        return NO_UPDATE_STATUS;
      }
      return buildConnectorUpdateStatus(cn.manager_contract.contract_version, versionsBySlug.get(slug) ?? [], { platformVersion: PLATFORM_VERSION });
    });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to compute the connectors update status', { module: 'connector', error });
    return connectorsToCheck.map(() => NO_UPDATE_STATUS);
  }
};

const filterConnectors = (instances: any[], type: string, scope: string | null, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return pipe(
    filter((candidate: any) => candidate.connector_type === type),
    filter((candidate: any) => !onlyAlive || candidate.active === true),
    filter((candidate: any) => !onlyAuto || candidate.auto === true),
    filter((candidate: any) => !onlyContextual || candidate.only_contextual === true),
    filter((candidate: any) => !scope
      || !candidate.connector_scope?.length
      || includes(scope.toLowerCase(), map((value: string) => value.toLowerCase(), candidate.connector_scope))),
  )(instances) as any[];
};

export const connectorsFor = async (
  context: AuthContext,
  user: AuthUser,
  type: string,
  scope: string | null,
  onlyAlive = false,
  onlyAuto = false,
  onlyContextual = false,
) => filterConnectors(await connectors(context, user), type, scope, onlyAlive, onlyAuto, onlyContextual);

export const connectorsForEnrichment = (
  context: AuthContext,
  user: AuthUser,
  scope: string,
  onlyAlive = false,
  onlyAuto = false,
) => connectorsFor(context, user, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);

export const connectorsEnrichment = (instances: any[], scope: string, onlyAlive = false, onlyAuto = false) => {
  return filterConnectors(instances, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsForImport = (
  context: AuthContext,
  user: AuthUser,
  scope: string,
  onlyAlive = false,
  onlyAuto = false,
  onlyContextual = false,
): Promise<BasicStoreEntityConnector[]> => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForExport = (
  context: AuthContext,
  user: AuthUser,
  scope: string | null = null,
  onlyAlive = false,
) => connectorsFor(context, user, CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);

export const connectorsForAnalysis = (
  context: AuthContext,
  user: AuthUser,
  scope: string | null = null,
  onlyAlive = true,
  onlyAuto = false,
  onlyContextual = false,
) => connectorsFor(context, user, CONNECTOR_INTERNAL_ANALYSIS, scope, onlyAlive, onlyAuto, onlyContextual);

export const connectorsForNotification = async (
  context: AuthContext,
  user: AuthUser,
  scope: string,
  onlyAlive = false,
  onlyAuto = false,
  onlyContextual = false,
) => [
  ...await connectorsFor(context, user, CONNECTOR_INTERNAL_NOTIFICATION, scope, onlyAlive, onlyAuto, onlyContextual),
  // TODO Built-in notifiers should be declared by the notifier module through the built-in connector registry
  //  (see connector-built-in-domain.ts)
  ...Object.values(BUILTIN_NOTIFIERS_CONNECTORS),
];

export const connectorsForPlaybook = async (context: AuthContext, user: AuthUser) => {
  return (await connectors(context, user)).filter((registeredConnector) => registeredConnector.playbook_compatible === true);
};

// TODO The sync, playbook, background task and PIR worker queues should be declared by their own modules through the
//  built-in connector registry (see connector-built-in-domain.ts) instead of being hardcoded here.
export const connectorsForWorker = async (context: AuthContext, user: AuthUser) => {
  const registeredConnectors = await connectors(context, user);
  registeredConnectors.push(
    { id: 'sync', name: '[DEPRECATED] Internal sync manager', connector_scope: [], config: connectorConfig('sync'), active: true },
    { id: 'playbook', name: '[DEPRECATED] Internal playbook manager', connector_scope: [], config: connectorConfig('playbook'), active: true },
  );
  const syncs = await fullEntitiesList(context, user, [ENTITY_TYPE_SYNC]);
  syncs.forEach((sync) => registeredConnectors.push({
    id: sync.internal_id, name: `Sync ${sync.internal_id} queue`, connector_scope: [], config: connectorConfig(sync.internal_id), active: true,
  }));
  const playbookPriority = booleanConf('playbook_manager:realtime_priority', false)
    ? ConnectorPriorityGroup.Realtime
    : ConnectorPriorityGroup.Default;
  const playbooks = await fullEntitiesList(context, user, [ENTITY_TYPE_PLAYBOOK]);
  playbooks.forEach((playbook) => registeredConnectors.push({
    id: playbook.internal_id, name: `Playbook ${playbook.internal_id} queue`, connector_scope: [],
    config: connectorConfig(playbook.internal_id), connector_priority_group: playbookPriority, active: true,
  }));
  for (let index = 0; index < BACKGROUND_TASK_QUEUES; index += 1) {
    registeredConnectors.push({
      id: `background-task-${index}`, name: `Background task ${index} queue`, connector_scope: [],
      config: connectorConfig(`background-task-${index}`), active: true,
    });
  }
  const pirs = await fullEntitiesList(context, user, [ENTITY_TYPE_PIR], { includeAuthorities: true });
  pirs.forEach((pir) => registeredConnectors.push({
    id: pir.internal_id, name: `Pir ${pir.internal_id} queue`, connector_scope: [], config: connectorConfig(pir.internal_id), active: true,
  }));
  return registeredConnectors;
};

export const computeManagerConnectorContract = async (_context: AuthContext, _user: AuthUser, connectorEntity: any) => {
  if (!connectorEntity.manager_contract) {
    return null;
  }
  return JSON.stringify(mapContractEntityFieldsToGraphqlCatalogContract(connectorEntity.manager_contract, { excludeRuntimeConfigVars: true }));
};

export const computeManagerConnectorExcerpt = async (_context: AuthContext, _user: AuthUser, connectorEntity: any) => {
  if (!connectorEntity.manager_contract) {
    return null;
  }
  const managerContract = connectorEntity.manager_contract;
  return { title: managerContract.title, slug: managerContract.slug, logo: managerContract.logo_uri ?? '' };
};

const COMPOSER_TOKEN_REDIS_EXPIRATION = conf.get('app:composer_token_expiration') ?? 604800;
const computeConnectorTokenConfiguration = async (context: AuthContext, connectorEntity: any) => {
  const resourceId = `manager-configuration-${connectorEntity.internal_id}`;
  let lock;
  try {
    lock = await lockResources([resourceId]);
    const users = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    const targetUser: any = users.get(connectorEntity.connector_user_id);
    const tokenName = 'Composer managed token';
    const existingToken = (targetUser.api_tokens ?? []).find((token: any) => token.name === tokenName);
    const redisClient = getClientBase();
    const key = `composer:${connectorEntity.catalog_id}:token:${connectorEntity.connector_user_id}`;
    let encryptedToken = await redisClient.get(key);
    if (isEmptyField(existingToken) || isEmptyField(encryptedToken)) {
      if (existingToken) {
        await revokeUserTokenByAdmin(context, SYSTEM_USER, connectorEntity.connector_user_id, existingToken.id);
      }
      const { plaintext_token } = await addUserTokenByAdmin(context, SYSTEM_USER, connectorEntity.connector_user_id, { name: tokenName } as any);
      const [manager] = await findConnectorManagers(context, SYSTEM_USER);
      encryptedToken = encryptValue(manager.public_key, plaintext_token);
      await redisClient.setex(key, COMPOSER_TOKEN_REDIS_EXPIRATION, encryptedToken);
    } else {
      await redisClient.expire(key, COMPOSER_TOKEN_REDIS_EXPIRATION);
    }
    return encryptedToken;
  } catch (error) {
    if ((error as { name?: string }).name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [resourceId] });
    }
    throw error;
  } finally {
    await lock?.unlock();
  }
};

export const computeManagerConnectorConfiguration = async (
  context: AuthContext,
  _user: AuthUser,
  connectorEntity: any,
  { withEncrypted = false }: { withEncrypted?: boolean } = {},
) => {
  if (!connectorEntity.catalog_id) {
    return [];
  }
  const configurations = structuredClone(connectorEntity.manager_contract_configuration) ?? [];
  const contract = withEncrypted ? configurations : configurations.filter((configuration: any) => !configuration.encrypted);
  contract.push(
    { key: 'CONNECTOR_ID', value: connectorEntity.internal_id },
    { key: 'CONNECTOR_NAME', value: connectorEntity.name },
    { key: 'CONNECTOR_TYPE', value: connectorEntity.connector_type },
  );
  if (withEncrypted) {
    contract.push({ key: 'OPENCTI_TOKEN', value: await computeConnectorTokenConfiguration(context, connectorEntity), encrypted: true });
  }
  return injectProxyConfiguration(contract).sort();
};

export const computeManagerConnectorImage = async (connectorEntity: any) => {
  if (!connectorEntity.manager_contract) {
    return '';
  }
  const managerContract = connectorEntity.manager_contract;
  if (!managerContract.image || !managerContract.contract_version) {
    throw FunctionalError('Invalid manager contract snapshot', {
      connectorId: connectorEntity.id ?? connectorEntity.internal_id,
      image: managerContract.image,
      version: managerContract.contract_version,
    });
  }
  return `${managerContract.image}:${managerContract.contract_version}`;
};

export const computeManagerContractHash = async (context: AuthContext, user: AuthUser, connectorEntity: any) => {
  const image = await computeManagerConnectorImage(connectorEntity);
  const configuration = await computeManagerConnectorConfiguration(context, user, connectorEntity, { withEncrypted: true });
  return shortHash({
    image,
    subHash: configuration.map((configuration: any) => `${configuration.key}|${configuration.value}`),
    state: connectorEntity.connector_state_timestamp,
  });
};

// region connectors
export const updateConnectorWithConnectorInfo = async (
  context: AuthContext,
  user: AuthUser,
  connectorEntity: BasicStoreEntityConnector,
  state: string,
  connectorInfo: ConnectorInfo,
) => {
  // Patch the state if needed. Liveness is not tracked here but in redis (see redisSetConnectorHeartbeat)
  let connectorPatch;

  if (connectorEntity.connector_state_reset) {
    connectorPatch = { connector_state_reset: false };
  } else {
    connectorPatch = { connector_state: state };
  }

  if (connectorInfo) {
    const connectorInfoData: ConnectorInfo = {
      run_and_terminate: connectorInfo.run_and_terminate,
      buffering: connectorInfo.buffering,
      queue_threshold: connectorInfo.queue_threshold,
      queue_messages_size: connectorInfo.queue_messages_size,
      next_run_datetime: connectorInfo.next_run_datetime,
      last_run_datetime: connectorInfo.last_run_datetime,
    };

    connectorPatch = { ...connectorPatch, connector_info: connectorInfoData };
  }
  const { element } = await patchAttribute<StoreEntityConnector>(context, user, connectorEntity.id, ENTITY_TYPE_CONNECTOR, connectorPatch);
  return element;
};

export const pingConnector = async (context: AuthContext, user: AuthUser, id: string, state: string, connectorInfo: ConnectorInfo) => {
  const connectorEntity = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!connectorEntity) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  // Ensure queue are correctly setup
  const scopes = connectorEntity.connector_scope ? connectorEntity.connector_scope.split(',') : [];
  await registerConnectorQueues(connectorEntity.id, connectorEntity.name, connectorEntity.connector_type, scopes);

  const lastSeenAt = now();
  // Not best effort: recording the heartbeat is the purpose of the ping, the connector must know it failed and retry.
  // Recorded before updating the state: a pending state reset is consumed by the update, failing after it would let
  // the connector, which never received the reset state, write back its stale one on its next ping
  await redisSetConnectorHeartbeat(connectorEntity.internal_id, lastSeenAt);
  const updatedConnector = await updateConnectorWithConnectorInfo(context, user, connectorEntity, state, connectorInfo);
  return completeConnector(updatedConnector, lastSeenAt);
};
export const resetStateConnector = async (context: AuthContext, user: AuthUser, id: string) => {
  const patch = { connector_state: '', connector_state_reset: true, connector_state_timestamp: now() };
  const { element } = await patchAttribute<StoreEntityConnector>(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `resets \`state\` and purge queues for ${ENTITY_TYPE_CONNECTOR} \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_CONNECTOR, input: patch },
  });
  await purgeConnectorQueues(element);
  return completeConnector(element, await loadConnectorHeartbeat(element.internal_id));
};
// Best effort: the next ping of the connector records its heartbeat anyway,
// and a failed registration would prevent the connector from starting.
const recordRegistrationHeartbeat = async (connectorId: string, lastSeenAt: string) => {
  try {
    await redisSetConnectorHeartbeat(connectorId, lastSeenAt);
  } catch (err) {
    logApp.warn('[OPENCTI-MODULE] Unable to record connector heartbeat on registration', { cause: err, connectorId });
  }
};
interface RegisterOptions {
  built_in?: boolean;
  active?: boolean;
  connector_user_id?: string | null;
  connector_priority_group?: ConnectorPriorityGroup;
}

export const registerConnectorsManager = async (context: AuthContext, user: AuthUser, input: RegisterConnectorsManagerInput) => {
  const manager = await storeLoadById(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER);
  const patch = { name: input.name, last_sync_execution: now(), public_key: input.public_key };
  if (manager) {
    const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER, patch);
    return element;
  }
  // Multiple connectors managers for one instance are not yet correctly supported.
  // Prevent new registration if already one manager is registered
  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
  if (connectorManagers.length > 0) {
    throw UnsupportedError('Only one connector manager is supported per instance', { id: input.id });
  }
  const managerToCreate = { internal_id: input.id, ...patch };
  return createEntity(context, user, managerToCreate, ENTITY_TYPE_CONNECTOR_MANAGER);
};

export const updateConnectorManagerStatus = async (context: AuthContext, user: AuthUser, input: UpdateConnectorManagerStatusInput) => {
  const patch: any = { last_sync_execution: now() };
  const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER, patch);
  return element;
};

export const managedConnectorEdit = async (
  context: AuthContext,
  user: AuthUser,
  input: EditManagedConnectorInput,
) => {
  const conn = await storeLoadById<BasicStoreEntityConnector>(context, user, input.id, ENTITY_TYPE_CONNECTOR);
  if (isEmptyField(conn)) {
    throw UnsupportedError('Connector not found', { id: input.id });
  }
  const targetContract = conn.manager_contract;
  if (!targetContract) {
    throw UnsupportedError('Target contract not found');
  }
  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
  if (connectorManagers?.length < 1) {
    throw FunctionalError('There is no connector manager configured');
  }
  const currentManager = connectorManagers[0];
  const contractConfigurations = computeConnectorTargetContract(
    input.manager_contract_configuration,
    targetContract,
    currentManager.public_key,
    conn.manager_contract_configuration,
  );
  const patch: any = {
    name: input.name,
    title: input.title,
    connector_type: targetContract.connector_type,
    connector_user_id: input.connector_user_id,
    manager_contract_configuration: contractConfigurations,
  };

  const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR, patch);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `creates ${ENTITY_TYPE_CONNECTOR} \`${input.name}\``,
    context_data: {
      entity_type: ENTITY_TYPE_CONNECTOR, id: input.id, input: {
        id: input.id,
        name: input.name,
        title: input.title,
        connector_user_id: input.connector_user_id,
      },
    },
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return element;
};

export const managedConnectorAdd = async (
  context: AuthContext,
  user: AuthUser,
  input: AddManagedConnectorInput,
) => {
  await checkEnterpriseEdition(context);
  // Get contract
  const targetContract = await findLatestCompatibleCatalogContractByImageName(context, user, input.manager_contract_image);
  if (isEmptyField(targetContract)) {
    // Distinguish an unknown connector from a connector that the platform version cannot run
    const imageContracts = await findCatalogContractsByImageName(context, user, input.manager_contract_image);
    if (imageContracts.length > 0) {
      throw FunctionalError('This connector is not compatible with the platform version', {
        image: input.manager_contract_image,
        platformVersion: PLATFORM_VERSION,
      });
    }
    throw UnsupportedError('Target contract not found');
  }
  if (!targetContract.manager_supported) {
    throw FunctionalError('You have not chosen a connector supported by the manager');
  }
  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
  if (connectorManagers?.length < 1) {
    throw FunctionalError('There is no connector manager configured');
  }
  const currentManager = connectorManagers[0];
  const contractConfigurations = computeConnectorTargetContract(input.manager_contract_configuration, targetContract, currentManager.public_key);
  // Get user
  if (input.user_id.length < 2) {
    throw FunctionalError('You have not chosen a user responsible for data creation', {});
  }
  let finalUserId = input.user_id;
  if (input.automatic_user) {
    const onTheFlyCreatedUser = await createOnTheFlyUser(
      context,
      user,
      { userName: input.user_id, serviceAccount: true, confidenceLevel: input.confidence_level ? parseInt(input.confidence_level, 10) : null },
    );
    finalUserId = onTheFlyCreatedUser.id;
  }
  const connectorUser = await storeLoadById(context, user, finalUserId, ENTITY_TYPE_USER);
  if (isEmptyField(connectorUser)) {
    throw UnsupportedError('Connector user not found', { id: finalUserId });
  }
  // Sanitize name
  const sanitizedName = sanitizeContainerName(input.name);
  if (!sanitizedName || sanitizedName.length < 2) {
    throw FunctionalError('Invalid connector name');
  }
  // Check for name collision
  const existingConnectors = await connectors(context, user);
  const nameCollision = existingConnectors.find((c) => c.name === sanitizedName);
  if (nameCollision) {
    logApp.info(`[CONNECTOR] Name collision detected: connector with name '${sanitizedName}' already exists`);
    throw FunctionalError('CONNECTOR_NAME_ALREADY_EXISTS');
  }

  // Create connector
  const connectorToCreate: any = {
    title: input.name,
    name: sanitizedName,
    connector_type: targetContract.connector_type,
    catalog_id: input.catalog_id,
    connector_user_id: connectorUser.id,
    manager_contract_image: input.manager_contract_image,
    manager_contract_configuration: contractConfigurations,
    manager_contract: mapContractEntityFieldsToEmbeddedConnectorManagerContract(targetContract),
    manager_upgrade_strategy: 'latest',
    manager_requested_status: 'stopped',
    connector_state_timestamp: now(),
    built_in: false,
  };

  const createdConnector: any = await createEntity(context, user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  // Increment telemetry for connector deployed via composer
  await addConnectorDeployedCount();
  // Publish
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${ENTITY_TYPE_CONNECTOR} \`${createdConnector.name}\``,
    context_data: { id: createdConnector.internal_id, entity_type: ENTITY_TYPE_CONNECTOR, input },
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, createdConnector, user);
  // Return the connector

  return completeConnector(createdConnector);
};

export const registerConnector = async (
  context: AuthContext,
  user: AuthUser,
  connectorData: RegisterConnectorInput,
  opts: RegisterOptions = {},
) => {
  const { id, name, type, scope, only_contextual = null, playbook_compatible = false, listen_callback_uri } = connectorData;
  const { auto = null, auto_update = null, enrichment_resolution = null, xtm_one_intent = null } = connectorData;
  const { version = null, slug = null } = connectorData;
  if (!isEmptyField(version) && !semver.valid(version) && version !== 'rolling') {
    logApp.warn('[OPENCTI-MODULE] Connector version is not a valid format', {
      version,
      module: 'connector',
    });
  }
  const conn = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  // A registration comes from the running connector itself: it is a heartbeat. Except for built-in connectors,
  // registered by the platform, whose liveness is their configured `active` (see isConnectorActive)
  const lastSeenAt = opts.built_in ? null : now();
  if (conn) {
    // Simple connector update
    const patch: any = {
      name,
      connector_type: type,
      connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
      auto,
      auto_update,
      enrichment_resolution,
      only_contextual,
      playbook_compatible,
      listen_callback_uri,
      xtm_one_intent,
      version,
      slug,
      connector_user_id: opts.connector_user_id ?? user.id,
      built_in: opts.built_in ?? false,
    };
    if (opts.active !== undefined) {
      patch.active = opts.active;
    }
    const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
    // Before notifying: the connectors cache must not reload the connector without its heartbeat
    if (lastSeenAt) {
      await recordRegistrationHeartbeat(id, lastSeenAt);
    }
    // Notify configuration change for caching system
    await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
    return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data, lastSeenAt));
  }
  // Need to create the connector
  const connectorToCreate: any = {
    internal_id: id,
    name,
    connector_type: type,
    connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
    auto,
    auto_update,
    enrichment_resolution,
    only_contextual,
    playbook_compatible,
    listen_callback_uri,
    xtm_one_intent,
    version,
    slug,
    connector_user_id: opts.connector_user_id ?? user.id,
    connector_state_timestamp: now(),
    built_in: opts.built_in ?? false,
    connector_priority_group: opts.connector_priority_group ?? ConnectorPriorityGroup.Default,
  };
  if (opts.active !== undefined) {
    connectorToCreate.active = opts.active;
  }
  const createdConnector = await createEntity(context, user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${ENTITY_TYPE_CONNECTOR} \`${createdConnector.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_CONNECTOR, input: connectorData },
  });
  // Before notifying: the connectors cache must not load the connector without its heartbeat
  if (lastSeenAt) {
    await recordRegistrationHeartbeat(id, lastSeenAt);
  }
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, createdConnector, user);
  // Return the connector
  return completeConnector(createdConnector, lastSeenAt);
};

export const connectorDelete = async (context: AuthContext, user: AuthUser, connectorId: string) => {
  await deleteWorkForConnector(context, user, connectorId);
  await unregisterConnector(connectorId);
  const { element } = await internalDeleteElementById<StoreEntityConnector>(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
  try {
    await redisDeleteConnectorHeartbeat(element.internal_id);
  } catch (err) {
    // Best effort: the connector is already deleted, an orphan heartbeat is never read
    logApp.warn('[OPENCTI-MODULE] Unable to delete connector heartbeat', { cause: err, connectorId });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ${ENTITY_TYPE_CONNECTOR} \`${element.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input: element },
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  return element.internal_id;
};

const updateConnector = async (context: AuthContext, user: AuthUser, connectorId: string, input: EditInput[]) => {
  const { element } = await updateAttribute<StoreEntityConnector>(context, user, connectorId, ENTITY_TYPE_CONNECTOR, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for connector \`${element.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input },
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ENTITY_TYPE_CONNECTOR].EDIT_TOPIC, element, user);
  return completeConnector(element, await loadConnectorHeartbeat(element.internal_id));
};

export const connectorUpdateLogs = async (_context: AuthContext, _user: AuthUser, input: LogsConnectorStatusInput) => {
  await redisSetConnectorLogs(input.id, input.logs);
  return input.id;
};

// Health metrics update function
export const connectorUpdateHealth = async (_context: AuthContext, _user: AuthUser, input: HealthConnectorStatusInput) => {
  const metrics: ConnectorHealthMetrics = {
    restart_count: input.restart_count,
    started_at: input.started_at,
    is_in_reboot_loop: input.is_in_reboot_loop,
    last_update: new Date().toISOString(),
  };
  await redisSetConnectorHealthMetrics(input.id, metrics);
  return input.id;
};

// Get health metrics function
export const connectorGetHealth = async (_context: AuthContext, _user: AuthUser, connectorId: string): Promise<ConnectorHealthMetrics | null> => {
  return redisGetConnectorHealthMetrics(connectorId);
};

// Get connector uptime in seconds
export const connectorGetUptime = async (context: AuthContext, user: AuthUser, connectorId: string): Promise<number | null> => {
  const healthMetrics = await connectorGetHealth(context, user, connectorId);
  if (!healthMetrics?.started_at) {
    return null;
  }
  // Parse ISO8601 format from xtm-composer
  const startDate = new Date(healthMetrics.started_at);
  if (Number.isNaN(startDate.getTime())) {
    return null;
  }
  const uptimeInSeconds = Math.floor((Date.now() - startDate.getTime()) / 1000);
  // Return uptime if positive, null otherwise
  return uptimeInSeconds >= 0 ? uptimeInSeconds : null;
};

export const updateConnectorRequestedStatus = async (context: AuthContext, user: AuthUser, input: RequestConnectorStatusInput) => {
  const ediInput: EditInput[] = [{ key: 'manager_requested_status', value: [input.status] }];
  return updateConnector(context, user, input.id, ediInput);
};

export const updateConnectorCurrentStatus = async (context: AuthContext, user: AuthUser, input: CurrentConnectorStatusInput) => {
  const ediInput: EditInput[] = [{ key: 'manager_current_status', value: [input.status] }];
  return updateConnector(context, user, input.id, ediInput);
};

export const connectorTriggerUpdate = async (context: AuthContext, user: AuthUser, connectorId: string, input: EditInput[]) => {
  const conn = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!conn) {
    throw FunctionalError('Cant find element to update', { id: connectorId, type: ENTITY_TYPE_CONNECTOR });
  }
  if (!['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE'].includes(conn.connector_type)) {
    throw FunctionalError('Update is only possible on internal enrichment or import file connectors types', { connectorId });
  }
  const supportedInputKeys = ['connector_trigger_filters'];
  if (input.some((item) => !supportedInputKeys.includes(item.key))) {
    throw FunctionalError(`Update is only possible on these input keys: ${supportedInputKeys.join(', ')}`, { connectorId });
  }
  const filtersItem: EditInput | undefined = input.find((item: EditInput) => item.key === 'connector_trigger_filters');
  if (filtersItem && filtersItem.value.length > 0) {
    const jsonFilters = JSON.parse(filtersItem.value[0]);
    if (isFilterGroupNotEmpty(jsonFilters)) {
      // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(jsonFilters);
    } else {
      filtersItem.value[0] = ''; // empty filter
    }
  }
  return updateConnector(context, user, connectorId, input);
};
// endregion

export const queueDetails = async (connectorId: string) => {
  return getConnectorQueueDetails(connectorId);
};

export const connectorUser = async (context: AuthContext, user: AuthUser, userId: string) => {
  if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    return platformUsers.get(userId);
  }
  return null;
};

const autoUpgradeManagedConnector = async (
  context: AuthContext,
  user: AuthUser,
  managedConnector: BasicStoreEntityConnector,
) => {
  const { manager_upgrade_strategy, manager_contract } = managedConnector;
  // Currently we only support the "upgrade to latest compatible version" strategy
  const managerUpgradeStrategy = manager_upgrade_strategy ?? 'latest';
  if (managerUpgradeStrategy !== 'latest') {
    return true;
  }
  if (!manager_contract) {
    logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, unable to find manager_contract on managed connector', {
      module: 'connector',
      connectorId: managedConnector.id,
    });
    return true;
  }
  const { slug, contract_version, content_hash } = manager_contract;
  try {
    const latestCompatibleContract = await findLatestCompatibleCatalogContractBySlug(context, user, slug);
    if (!latestCompatibleContract) {
      // Warning: we're running a connector that's not compatible anymore but
      // there's no replacement version compatible !
      logApp.warn('[OPENCTI-MODULE] Unable to find a compatible contract when applying auto-upgrade-to-latest-compatible strategy', {
        module: 'connector',
        connectorId: managedConnector.id,
      });
      return true;
    }
    const versionComparison = compareContractVersions(contract_version, latestCompatibleContract.contract_version);
    if (versionComparison === 0
      && content_hash === latestCompatibleContract.content_hash) {
      logApp.debug('[OPENCTI-MODULE] Managed connector already uses latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        version: contract_version,
      });
      return true;
    }
    // Update connector
    const patch: Partial<BasicStoreEntityConnector> = {
      manager_contract: mapContractEntityFieldsToEmbeddedConnectorManagerContract(latestCompatibleContract),
      manager_contract_image: latestCompatibleContract.image,
    };
    await patchAttribute(context, user, managedConnector.id, ENTITY_TYPE_CONNECTOR, patch);
    if (versionComparison < 0) {
      logApp.info('[OPENCTI-MODULE] Upgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: contract_version,
        newVersion: latestCompatibleContract.contract_version,
      });
      // Activity log
      // Unsure how correct this is. Maybe the context_data is too big here.
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'upgrades connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    } else if (versionComparison > 0) {
      logApp.info('[OPENCTI-MODULE] Downgraded connector to latest compatible version', {
        module: 'connector',
        connectorId: managedConnector.id,
        contractSlug: slug,
        previousVersion: contract_version,
        newVersion: latestCompatibleContract.contract_version,
      });
      // Activity log
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'downgrades connector to latest compatible version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    } else {
      if (contract_version === 'rolling') {
        logApp.info('[OPENCTI-MODULE] Upgraded connector to latest compatible rolling', {
          module: 'connector',
          connectorId: managedConnector.id,
          contractSlug: slug,
          previousVersion: contract_version,
          newVersion: latestCompatibleContract.contract_version,
        });
      } else {
        // Shouldn't happen: either a Release issue or a logic/code error.
        logApp.warn('[OPENCTI-MODULE] Inconsistent connector data, same connector version with different contract content hash', {
          module: 'connector',
          contractSlug: slug,
          contractVersion: contract_version,
        });
      }
      // Activity log
      void publishUserAction({
        event_type: 'mutation',
        event_access: 'administration',
        event_scope: 'update',
        message: 'upgrades connector to latest compatible identical version',
        user,
        context_data: {
          entity_type: ENTITY_TYPE_CONNECTOR,
          id: managedConnector.id,
          input: {
            slug,
            previousVersion: contract_version,
            newVersion: latestCompatibleContract.contract_version,
          },
        },
      });
    }
    return true;
  } catch (exception) {
    logApp.error('[OPENCTI-MODULE] Failed to auto-upgrade connector to latest compatible version', {
      module: 'connector',
      contractSlug: slug,
      contractVersion: contract_version,
      cause: exception,
    });
    return false;
  }
};

export const autoUpgradeManagedConnectors = async (
  context: AuthContext,
  user: AuthUser,
  synchronizedCatalogIds: string[],
) => {
  const startedAt = Date.now();
  const currentStatus = await redisGetManagedConnectorAutoUpgradeStatus();
  const shouldUpdateReadiness = currentStatus?.platformVersion !== PLATFORM_VERSION
    || currentStatus.status === 'running';
  if (shouldUpdateReadiness) {
    await redisSetManagedConnectorAutoUpgradeStatus({
      status: 'running',
      platformVersion: PLATFORM_VERSION,
      startedAt,
    });
  }
  try {
    let hasErrors = false;
    for (const catalogId of synchronizedCatalogIds) {
      const managedConnectors = await findManagedConnectorsByCatalogId(context, user, catalogId);
      for (const managedConnector of managedConnectors) {
        const upgradedSuccessfully = await autoUpgradeManagedConnector(context, user, managedConnector);
        hasErrors ||= !upgradedSuccessfully;
      };
    };
    if (shouldUpdateReadiness) {
      await redisSetManagedConnectorAutoUpgradeStatus({
        status: hasErrors ? 'failed' : 'ready',
        platformVersion: PLATFORM_VERSION,
        startedAt,
        completedAt: Date.now(),
        ...(hasErrors ? { error: 'One or more managed connectors failed to auto-upgrade' } : {}),
      });
    }
    return { hasErrors };
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to auto-upgrade managed connectors', {
      module: 'connector',
      cause: error,
    });
    if (shouldUpdateReadiness) {
      await redisSetManagedConnectorAutoUpgradeStatus({
        status: 'failed',
        platformVersion: PLATFORM_VERSION,
        startedAt,
        completedAt: Date.now(),
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return { hasErrors: true };
  }
};
