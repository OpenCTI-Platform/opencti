import type { AuthContext, AuthUser } from '../../types/user';
import { findCatalogByCatalogId, findLatestCompatibleCatalogContractByImageName } from '../catalog/catalog-repository';
import { computeConnectorTargetContract, getContractConfigSchemaWithoutExcludedRuntimeVars } from '../catalog/catalog-domain';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportValidationReason, freeConfigImportName, joinConfigImportReasons } from '../configImport/configImport-utils';
import { userAlreadyExists } from '../user/user-domain';
import { findDefaultIngestionGroups } from '../../domain/group';
import { storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreEntityUser } from '../user/user-types';
import { managedConnectorAdd, managedConnectorEdit, sanitizeContainerName } from './connector-domain';
import { findConnectorManagers, findConnectors } from './connector-repository';
import type { BasicStoreEntityConnector } from './connector-types';
import { connectorSecretKeys } from './connector-export';
import { type ConnectorImportConfiguration, connectorImportSchema } from './connector-import-schema';

export interface ConnectorImportLoaded {
  connectors: BasicStoreEntityConnector[];
  managers: { public_key: string }[];
}

export interface ConnectorImportOptions extends ConfigImportOptions {
  bundleId?: string;
  loaded?: ConnectorImportLoaded;
  reservedNames?: Set<string>;
  credentials?: Record<string, string>;
  ingestionGroupPlanned?: boolean;
  serviceAccountId?: string;
}

export interface ConnectorImportCredential {
  key: string;
  description: string;
  required: boolean;
  stored: boolean;
}

export type ConnectorImportCode = 'invalid' | 'not_available' | 'no_manager' | 'not_managed' | 'exists' | 'name_conflict' | 'credentials_required' | 'no_ingestion_group' | 'service_account_missing' | 'unchanged';

export const NO_INGESTION_GROUP_REASON = 'You have not defined a default group for ingestion users';
export const CONFIDENCE_NOT_CHANGED_REASON = 'The confidence level of the service account is not changed';

export type ConnectorImportResult = ConfigImportResult<ConnectorImportConfiguration, ConnectorImportCode> & {
  credentials?: ConnectorImportCredential[];
  connector?: BasicStoreEntityConnector;
};

const refused = (
  code: ConnectorImportCode,
  reason: string,
  exists: boolean,
  configuration?: ConnectorImportConfiguration,
  credentials?: ConnectorImportCredential[],
): ConnectorImportResult => ({ status: 'failed', code, reason, exists, configuration, credentials });

export const connectorName = (title: string) => sanitizeContainerName(title);

export const loadConnectorImportContext = async (context: AuthContext, user: AuthUser): Promise<ConnectorImportLoaded> => {
  const [connectors, managers] = await Promise.all([findConnectors(context, user), findConnectorManagers(context, user)]);
  return { connectors, managers };
};

const freeServiceAccountName = (context: AuthContext, title: string) => {
  return freeConfigImportName(`[C] ${title}`, (candidate) => userAlreadyExists(context, candidate));
};

const sameConfiguration = (current: { key: string; value?: string | null }[], input: { key: string; value: string }[]) => {
  return current.length === input.length && input.every(({ key, value }) => current.some((configuration) => configuration.key === key && (configuration.value ?? '') === value));
};

// add: the connector must not exist yet. overwrite: the managed connector with the same name is updated, else it is created.
// copy: the connector is created under a free name. A created connector is stopped.
export const importConnector = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: ConnectorImportOptions,
): Promise<ConnectorImportResult> => {
  const { mode, dryRun = false, bundleId, loaded, reservedNames, credentials = {}, ingestionGroupPlanned = false, serviceAccountId } = options;
  const parsed = connectorImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  const bundleConnector = parsed.data;
  const { connectors, managers } = loaded ?? await loadConnectorImportContext(context, user);
  const isNameTaken = async (candidate: string) => {
    const name = connectorName(candidate);
    return !!reservedNames?.has(name) || connectors.some((connector) => connector.name === name);
  };
  const sameName = connectors.find(({ name }) => name === connectorName(bundleConnector.name));
  const isSameConnector = sameName?.catalog_id === bundleConnector.catalog_id && sameName?.manager_contract_image === bundleConnector.manager_contract_image;
  const existing = connectors.find(({ name }) => name === (bundleId ?? connectorName(bundleConnector.name))) ?? (isSameConnector ? sameName : undefined);
  if (existing && mode === ConfigImportMode.Add) {
    return refused('exists', 'Connector already exists', true, bundleConnector);
  }
  const isCopy = mode === ConfigImportMode.Copy;
  if (!existing && sameName && !isCopy) {
    return refused('name_conflict', 'Connector name already exists', true, bundleConnector);
  }
  if (existing && !isCopy && !existing.catalog_id) {
    return refused('not_managed', 'A connector that is not managed by the platform has this name', true, bundleConnector);
  }
  const title = isCopy ? await freeConfigImportName(bundleConnector.name, isNameTaken) : bundleConnector.name;
  if (!title) {
    return refused('name_conflict', 'Connector name already exists', !!existing, bundleConnector);
  }
  const target = isCopy ? undefined : existing;
  const catalog = await findCatalogByCatalogId(context, user, bundleConnector.catalog_id);
  const contract = target?.manager_contract
    ?? (catalog ? await findLatestCompatibleCatalogContractByImageName(context, user, bundleConnector.manager_contract_image, bundleConnector.catalog_id) : undefined);
  if (!contract || (!target && !contract.manager_supported)) {
    return refused('not_available', `Connector not available on this platform: ${bundleConnector.manager_contract_image}`, !!existing, bundleConnector);
  }
  const [manager] = managers;
  if (!manager) {
    return refused('no_manager', 'There is no connector manager configured', !!existing, bundleConnector);
  }
  const configSchema = getContractConfigSchemaWithoutExcludedRuntimeVars(contract.config_schema);
  const secretKeys = connectorSecretKeys(configSchema);
  const currentKeys = (target?.manager_contract_configuration ?? []).map(({ key }) => key);

  const connectorCredentials: ConnectorImportCredential[] = secretKeys
    .filter((key) => configSchema.required.includes(key) || bundleConnector.required_at_import.includes(key))
    .map((key) => ({ key, description: configSchema.properties[key]?.description ?? '', required: configSchema.required.includes(key), stored: currentKeys.includes(key) }));
  const given = connectorCredentials.filter(({ key }) => (credentials[key] ?? '') !== '');
  const missing = connectorCredentials.filter(({ key, required, stored }) => required && !stored && !given.some((credential) => credential.key === key));
  if (missing.length > 0) {
    return refused('credentials_required', `Credentials to provide: ${missing.map(({ key }) => key).join(', ')}`, !!existing, bundleConnector, connectorCredentials);
  }
  if (!target && serviceAccountId && !(await storeLoadById(context, user, serviceAccountId, ENTITY_TYPE_USER))) {
    return refused('service_account_missing', 'Service account not found', !!existing, bundleConnector, connectorCredentials);
  }
  if (!target && !serviceAccountId && !ingestionGroupPlanned && (await findDefaultIngestionGroups(context, user)).length === 0) {
    return refused('no_ingestion_group', NO_INGESTION_GROUP_REASON, !!existing, bundleConnector, connectorCredentials);
  }
  const parameters = bundleConnector.manager_contract_configuration.filter(({ key }) => configSchema.properties[key] && !secretKeys.includes(key));
  const keptSecrets = (target?.manager_contract_configuration ?? [])
    .filter(({ key, value, encrypted }) => !encrypted && value && secretKeys.includes(key) && !given.some((credential) => credential.key === key))
    .map(({ key, value }) => ({ key, value: value as string }));
  const input = [...parameters, ...given.map(({ key }) => ({ key, value: credentials[key] })), ...keptSecrets];
  const { confidence_level: confidence } = bundleConnector;
  const connectorUser = target && confidence !== null && confidence !== undefined
    ? await storeLoadById<BasicStoreEntityUser>(context, user, target.connector_user_id, ENTITY_TYPE_USER)
    : undefined;
  const confidenceReason = connectorUser && connectorUser.user_confidence_level?.max_confidence !== confidence ? CONFIDENCE_NOT_CHANGED_REASON : undefined;
  if (target && given.length === 0 && (target.title ?? target.name) === title) {
    const currentParameters = (target.manager_contract_configuration ?? []).filter(({ key, encrypted }) => !encrypted && configSchema.properties[key] && !secretKeys.includes(key));
    if (sameConfiguration(currentParameters, parameters)) {
      const reason = joinConfigImportReasons([CONFIG_IMPORT_UNCHANGED_REASON, confidenceReason]);
      return { status: 'skipped', code: 'unchanged', reason, exists: true, configuration: bundleConnector, credentials: connectorCredentials };
    }
  }
  try {
    computeConnectorTargetContract(input, contract, manager.public_key, target?.manager_contract_configuration);
  } catch (error) {
    return refused('invalid', error instanceof Error ? error.message : String(error), !!existing, bundleConnector, connectorCredentials);
  }
  const reason = joinConfigImportReasons([title !== bundleConnector.name ? `Added as "${title}"` : undefined, confidenceReason]);
  const result: ConnectorImportResult = { status: target ? 'overwritten' : 'created', exists: !!existing, configuration: bundleConnector, reason, credentials: connectorCredentials };
  if (dryRun) {
    reservedNames?.add(connectorName(title));
    return result;
  }
  if (target) {
    const connector = await managedConnectorEdit(context, user, {
      id: target.id,
      name: target.name,
      title,
      connector_user_id: target.connector_user_id,
      manager_contract_configuration: input,
    });
    return { ...result, connector: connector as unknown as BasicStoreEntityConnector };
  }
  const serviceAccount = serviceAccountId
    ? { user_id: serviceAccountId, automatic_user: false }
    : {
        user_id: (await freeServiceAccountName(context, title)) ?? `[C] ${title}`,
        automatic_user: true,
        ...(confidence !== null && confidence !== undefined ? { confidence_level: String(confidence) } : {}),
      };
  const connector = await managedConnectorAdd(context, user, {
    name: title,
    catalog_id: bundleConnector.catalog_id,
    manager_contract_image: bundleConnector.manager_contract_image,
    manager_contract_configuration: input,
    ...serviceAccount,
  });
  return { ...result, connector: connector as unknown as BasicStoreEntityConnector };
};
