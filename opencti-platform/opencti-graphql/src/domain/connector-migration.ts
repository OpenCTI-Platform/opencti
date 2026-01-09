import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { patchAttribute } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { notify } from '../database/redis';
import { completeConnector, connector } from '../database/repository';
import type { Connector, ConnectorContractConfiguration, ContractConfigInput } from '../generated/graphql';
import { publishUserAction } from '../listener/UserActionListener';
import { addConnectorDeployedCount } from '../manager/telemetryManager';
import { computeConnectorTargetContract, findContractByContainerImage } from '../modules/catalog/catalog-domain';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER } from '../schema/internalObject';
import type { BasicStoreEntityConnectorManager } from '../types/connector';
import type { AuthContext, AuthUser } from '../types/user';
import { isServiceAccountUser } from '../utils/access';
import { resolveUserByIdFromCache, userEditField } from './user';

type ConfigInput = {
  key: string;
  value: string;
};

type MappedKey = {
  key: string;
  value: string;
  type: string;
  required: boolean;
  autoMapped?: boolean;
};

type MissingKey = {
  key: string;
  type: string;
  description: string;
  format?: string;
  required: boolean;
  default: any;
  enum: string[] | null;
};

type IgnoredKey = {
  key: string;
  value: string;
  reason: string;
};

const buildConfigMap = (configuration: ConfigInput[]): Map<string, string> => {
  const configMap = new Map<string, string>();

  configuration.forEach((c) => {
    configMap.set(c.key.toUpperCase(), c.value);
  });

  return configMap;
};

const autoMapConnectorFields = (connectorOjb: Connector): Map<string, string> => {
  const autoMapped = new Map<string, string>();

  if (connectorOjb.name) {
    autoMapped.set('CONNECTOR_NAME', connectorOjb.name);
  }

  if (connectorOjb.connector_scope) {
    autoMapped.set('CONNECTOR_SCOPE', connectorOjb.connector_scope.join(','));
  }

  if (connectorOjb.connector_type) {
    autoMapped.set('CONNECTOR_TYPE', connectorOjb.connector_type);
  }

  return autoMapped;
};

const categorizeKeys = (
  schemaProperties: any,
  requiredKeys: string[],
  configMap: Map<string, string>,
): { mapped: MappedKey[]; missing: MissingKey[] } => {
  const mapped: MappedKey[] = [];
  const missing: MissingKey[] = [];

  Object.keys(schemaProperties).forEach((schemaKey) => {
    const propSchema = schemaProperties[schemaKey];

    const keyUpper = schemaKey.toUpperCase();
    const value = configMap.get(keyUpper);

    if (value !== null && value !== undefined) {
      mapped.push({
        key: schemaKey,
        value: String(value),
        type: propSchema.type,
        required: requiredKeys.includes(schemaKey),
      });
    } else {
      missing.push({
        key: schemaKey,
        type: propSchema.type,
        description: propSchema.description || 'No description',
        format: propSchema.format,
        required: requiredKeys.includes(schemaKey),
        default: propSchema.default ?? null,
        enum: propSchema.enum ?? null,
      });
    }
  });

  return { mapped, missing };
};

const findIgnoredKeys = (schemaProperties: any, configMap: Map<string, string>): IgnoredKey[] => {
  const ignored: IgnoredKey[] = [];
  const schemaKeysUpper = new Set(
    Object.keys(schemaProperties).map((k) => k.toUpperCase()),
  );

  configMap.forEach((value: string, key: string) => {
    if (!schemaKeysUpper.has(key)) {
      ignored.push({
        key,
        value: String(value),
        reason: 'Not in target contract schema',
      });
    }
  });

  return ignored;
};

export const assessConnectorMigration = async (context: AuthContext, user: AuthUser, connectorId: string, containerImage: string, configuration: ConfigInput[]) => {
  const existingConnector = await connector(context, user, connectorId);

  if (!existingConnector) {
    throw FunctionalError('Connector not found', { id: connectorId });
  }

  if (existingConnector.is_managed) {
    throw FunctionalError('Connector is already managed', { id: connectorId });
  }

  const contractData = await findContractByContainerImage(context, user, containerImage);
  if (!contractData) {
    throw FunctionalError('Contract not found', { container_image: containerImage });
  }

  let contract;
  try {
    contract = JSON.parse(contractData.contract);
  } catch {
    throw FunctionalError('Cannot parse contract found');
  }

  // Check type are correct
  if (existingConnector.connector_type !== contract.container_type) {
    throw FunctionalError('Connector type mismatch', {
      connector_type: existingConnector.connector_type,
      contract_type: contract.container_type,
    });
  }

  // Build configuration maps
  const autoMappedConfig = autoMapConnectorFields(existingConnector);
  const userConfig = buildConfigMap(configuration || []);

  // Merge: auto-mapped first, then user config (user overrides auto)
  const configMap = new Map([...autoMappedConfig, ...userConfig]);

  // Categorize configuration keys
  const schemaProperties = contract.config_schema.properties;
  const requiredKeys = contract.config_schema.required || [];

  const { mapped, missing } = categorizeKeys(
    schemaProperties,
    requiredKeys,
    configMap,
  );

  const ignored = findIgnoredKeys(schemaProperties, configMap);

  // Build summary
  const missingMandatory = missing.filter((m) => m.required);

  return {
    connector_id: connectorId,
    connector_name: existingConnector.name,
    connector_type: existingConnector.connector_type,
    contract_slug: contract.contract_slug,
    contract_title: contract.title,
    contract_image: contract.container_image,
    summary: {
      total_source_keys: configMap.size,
      mapped_keys: mapped.length,
      ignored_keys: ignored.length,
      missing_mandatory_keys: missingMandatory.length,
      missing_optional_keys: missing.length - missingMandatory.length,
      can_migrate: missingMandatory.length === 0,
      configuration_provided: configuration !== null,
    },
    mapped,
    ignored,
    missing,
    message: configuration === null
      ? 'No configuration provided. You must provide configuration manually with exact schema keys.'
      : null,
  };
};

export const migrateConnectorToManaged = async (
  context: AuthContext,
  user: AuthUser,
  connectorId: string,
  containerImage: string,
  configuration: ConfigInput[] | null,
  convertUserToServiceAccount: boolean = true,
  resetConnectorState: boolean = false,
) => {
  const contractData = await findContractByContainerImage(context, user, containerImage);
  if (!contractData) {
    throw FunctionalError('Contract not found', { container_image: containerImage });
  }

  let contract;
  try {
    contract = JSON.parse(contractData.contract);
  } catch {
    throw FunctionalError('Cannot parse contract');
  }

  if (!contract.manager_supported) {
    throw FunctionalError('Connector is not managed by composer');
  }

  const existingConnector = await connector(context, user, connectorId);

  if (!existingConnector) {
    throw FunctionalError('Connector not found', { id: connectorId });
  }
  if (existingConnector.is_managed) {
    throw FunctionalError('Connector is already managed', { id: connectorId });
  }

  if (existingConnector.connector_type !== contract.container_type) {
    throw FunctionalError('Connector type mismatch', {
      connector_type: existingConnector.connector_type,
      contract_type: contract.container_type,
    });
  }

  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(
    context,
    user,
    [ENTITY_TYPE_CONNECTOR_MANAGER],
  );
  if (connectorManagers?.length < 1) {
    throw FunctionalError('No connector manager configured');
  }
  const currentManager = connectorManagers[0];

  const autoMappedConfig = autoMapConnectorFields(existingConnector);
  const userConfig = buildConfigMap(configuration || []);

  const configMap = new Map([...autoMappedConfig, ...userConfig]);

  const schemaProperties = contract.config_schema.properties;
  const schemaKeysUpper = new Set(
    Object.keys(schemaProperties).map((k) => k.toUpperCase()),
  );

  const invalidKeys: string[] = [];
  userConfig.forEach((value: string, key: string) => {
    if (!schemaKeysUpper.has(key)) {
      invalidKeys.push(key);
    }
  });

  if (invalidKeys.length > 0) {
    throw FunctionalError('Invalid configuration keys provided', {
      invalid_keys: invalidKeys,
      message: `The following keys do not exist in the contract schema: ${invalidKeys.join(', ')}`,
    });
  }

  const configurationArray: ContractConfigInput[] = Array.from(configMap.entries()).map(([key, value]) => ({
    key,
    value,
  }));

  let configurations: ConnectorContractConfiguration[];
  try {
    configurations = computeConnectorTargetContract(
      configurationArray,
      contract,
      currentManager.public_key,
    );
  } catch (err: any) {
    throw FunctionalError('Configuration validation failed', {
      message: err.message,
      details: err.data,
    });
  }

  // these fields are provided by the runtime resolver connector.manager_contract_definition
  // so remove them
  const RUNTIME_PROVIDED_FIELDS = ['CONNECTOR_NAME', 'CONNECTOR_ID', 'CONNECTOR_TYPE'];
  const filteredConfigurations = configurations.filter(
    (config) => !RUNTIME_PROVIDED_FIELDS.includes(config.key),
  );

  const existingUser = await resolveUserByIdFromCache(context, existingConnector.connector_user_id) as AuthUser;

  // If existing user is not a service account, transform it to service account
  if (
    !isServiceAccountUser(existingUser)
    && convertUserToServiceAccount
  ) {
    await userEditField(
      context,
      user,
      existingUser.id,
      [{ key: 'user_service_account', value: [true] }],
    );
  }

  const managedConnectorData: any = {
    title: existingConnector.name,
    catalog_id: contractData.catalog_id,
    manager_contract_image: contract.container_image,
    manager_contract_configuration: filteredConfigurations,
    manager_requested_status: 'stopped',
  };

  // Reset connector state if requested
  if (resetConnectorState && existingConnector.connector_state) {
    managedConnectorData.connector_state = null;
  }

  const { element } = await patchAttribute(
    context,
    user,
    existingConnector.id,
    ENTITY_TYPE_CONNECTOR,
    managedConnectorData,
  );

  const completedConnector = completeConnector(element);

  await addConnectorDeployedCount();

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `migrates connector \`${existingConnector.name}\` to managed`,
    context_data: {
      id: existingConnector.internal_id,
      entity_type: ENTITY_TYPE_CONNECTOR,
      input: managedConnectorData,
    },
  });

  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, completedConnector, user);

  return completedConnector;
};
