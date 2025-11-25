import { FunctionalError } from '../config/errors';
import { storeLoadById } from '../database/middleware-loader';
import { connector, connectorManagers } from '../database/repository';
import { findContractBySlug, getContractBySlug, getSupportedSlugs } from '../modules/catalog/catalog-domain';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import type { BasicStoreEntityConnector } from '../types/connector';
import type { AuthContext, AuthUser } from '../types/user';

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
  defaultValue: any;
  enum: string[] | null;
};

type IgnoredKey = {
  key: string;
  value: string;
  reason: string;
};

export const getConnector = async (context: AuthContext, user: AuthUser, id: string) => {
  const connectorFound = connector(context, user, id);

  if (!connectorFound) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
};

const checkComposerRegistered = async (context:AuthContext, user: AuthUser) => {
  const managers = await connectorManagers(context, user);
  return managers.length > 0;
};

export const migrateConnectorToManagedConnector = async (context:AuthContext, user: AuthUser, id: string) => {
  if (!checkComposerRegistered(context, user)) {
    throw FunctionalError('No registered composer found');
  }
};

export const assessConnectorMigration = async (context: AuthContext, user: AuthUser, connectorId: string, contractSlug: string, configuration: ConfigInput[]) => {
  const existingConnector = await connector(context, user, connectorId);

  if (!existingConnector) {
    throw FunctionalError('Connector not found', { id: connectorId });
  }

  if (existingConnector.is_managed) {
    throw FunctionalError('Connector is already managed', { id: connectorId });
  }

  const contractData = await findContractBySlug(context, user, contractSlug);
  if (!contractData) {
    throw FunctionalError('Contract not found', { slug: contractSlug });
  }

  let contract;
  try {
    contract = JSON.parse(contractData.contract);
  } catch (e) {
    throw FunctionalError('Cannot parse contract found');
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { logo, description, short_description, ...contractDefinition } = contract;

  if (existingConnector.connector_type !== contractDefinition.container_type) {
    throw FunctionalError('Connector type mismatch', {
      connector_type: existingConnector.connector_type,
      contract_type: contractDefinition.container_type
    });
  }

  const schemaProperties = contractDefinition.config_schema.properties;
  const requiredKeys = contractDefinition.config_schema.required || [];

  const sourceConfig = configuration || {};

  const configMap = new Map();
  if (Array.isArray(sourceConfig)) {
    sourceConfig.forEach((c) => {
      configMap.set(c.key.toUpperCase(), c.value);
    });
  } else {
    Object.entries(sourceConfig).forEach(([key, value]) => {
      configMap.set(key.toUpperCase(), value);
    });
  }

  const mapped: any[] = [];
  const missing: any[] = [];

  Object.keys(schemaProperties).forEach((schemaKey) => {
    const propSchema = schemaProperties[schemaKey];
    const value = configMap.get(schemaKey.toUpperCase());

    if (value !== null && value !== undefined) {
      mapped.push({
        key: schemaKey,
        value: String(value),
        type: propSchema.type,
        required: requiredKeys.includes(schemaKey)
      });
    } else {
      const isRequired = requiredKeys.includes(schemaKey);
      const hasDefault = propSchema.default !== undefined;

      missing.push({
        key: schemaKey,
        type: propSchema.type,
        description: propSchema.description || 'No description',
        format: propSchema.format,
        required: isRequired,
        defaultValue: hasDefault ? propSchema.default : null,
        enum: propSchema.enum ?? null
      });
    }
  });

  const ignored: any[] = [];
  const schemaKeysUpper = new Set(
    Object.keys(schemaProperties).map((k) => k.toUpperCase())
  );

  configMap.forEach((value: string, key: string) => {
    if (!schemaKeysUpper.has(key)) {
      ignored.push({
        key,
        value: String(value),
        reason: 'Not in target contract schema'
      });
    }
  });

  const missingMandatory = missing.filter((m) => m.required);

  return {
    connector_id: connectorId,
    connector_name: existingConnector.name,
    connector_type: existingConnector.connector_type,
    contract_slug: contractSlug,
    contract_title: contractDefinition.title,
    contract_image: contractDefinition.container_image,
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
      : null
  };
};

interface MigrationWarning {
  field?: string;
  message: string;
}

interface MigrateConnectorToManagedResult {
  connector: BasicStoreEntityConnector;
  warnings: MigrationWarning[];
  state_preserved: boolean;
  dryRun: boolean;
  skipped?: boolean;
}

export const migrateConnectorToManaged = async (
  context: AuthContext,
  user: AuthUser,
  connectorId: string,
  contractSlug: string,
  configuration: Array<{ key: string; value: string }> | null = null,
  preserveState: boolean = true,
  dryRun: boolean = false
): Promise<MigrateConnectorToManagedResult> => {
  // 1. Get connector
  const existingConnector = await connector(context, user, connectorId);
  if (!existingConnector) {
    throw FunctionalError('Connector not found', { id: connectorId });
  }

  // 2. Check if already managed
  if (existingConnector.is_managed) {
    return {
      connector: existingConnector,
      warnings: [{ message: 'Connector is already managed' }],
      state_preserved: false,
      dryRun,
      skipped: true
    };
  }

  // 3. Get contract by slug
  // TODO: Implement getContractBySlug

  // 4. Validate type compatibility
  // TODO: Implement validation

  // 5. Map configuration
  // TODO: Implement mapStandaloneConfigToContract

  // 6. Validate - check missing required fields
  // TODO: Implement findMissingRequiredFields

  // 7. Get manager for encryption
  // TODO: Implement getActiveConnectorManager

  // 8. Process config (with encryption)
  // TODO: Implement computeConnectorTargetContract

  // 9. Build update payload
  const updatePayload = {
    // TODO: Build payload
  };

  // 10. Generate warnings
  const warnings: MigrationWarning[] = [];
  // TODO: Generate warnings

  // 11. DRY RUN: Return without saving
  if (dryRun) {
    return {
      connector: { ...existingConnector, ...updatePayload, is_managed: true },
      warnings,
      state_preserved: preserveState,
      dryRun: true
    };
  }

  // 12. ACTUAL MIGRATION: Save to database
  // await elUpdateElement({
  //   _index: existingConnector._index,
  //   internal_id: existingConnector.internal_id,
  //   ...updatePayload
  // });

  // 13. Reload connector
  const migratedConnector = await connector(context, user, connectorId);

  return {
    connector: migratedConnector,
    warnings,
    state_preserved: preserveState && !!existingConnector.connector_state,
    dryRun: false
  };
};
