import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import crypto from 'crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntityCatalogContract,
  type BasicStoreEntityCatalog,
  type CatalogContract,
  type CatalogContractEntityFields,
  type GraphqlCatalog,
  type GraphqlCatalogContract,
} from './catalog-types';
import { isEmptyField } from '../../database/utils';
import { UnsupportedError } from '../../config/errors';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../generated/graphql';
import type { ValidateFunction } from 'ajv';
import { findCatalogByCatalogId, findCatalogs, findLatestCompatibleCatalogContractBySlug, findLatestCompatibleCatalogContractsByCatalogId } from './catalog-repository';
import { logApp } from '../../config/conf';

const validatorCache = new Map<string, ValidateFunction>();
const EXCLUDED_CONFIG_VARS = ['OPENCTI_TOKEN', 'OPENCTI_URL', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE'];

const normalizeContractConfigSchema = (
  configSchema: CatalogContract['config_schema'] | null | undefined,
): CatalogContract['config_schema'] => {
  const schema = (configSchema && typeof configSchema === 'object') ? configSchema : {} as CatalogContract['config_schema'];
  const properties = (schema.properties && typeof schema.properties === 'object' && !Array.isArray(schema.properties))
    ? schema.properties
    : {};
  const required = Array.isArray(schema.required) ? schema.required.filter((property) => typeof property === 'string') : [];
  return {
    $schema: typeof schema.$schema === 'string' ? schema.$schema : 'https://json-schema.org/draft/2020-12/schema',
    $id: typeof schema.$id === 'string' ? schema.$id : '',
    type: typeof schema.type === 'string' ? schema.type : 'object',
    properties,
    required,
    additionalProperties: typeof schema.additionalProperties === 'boolean' ? schema.additionalProperties : true,
  };
};

const getContractConfigSchemaWithoutExcludedRuntimeVars = (configSchema: CatalogContract['config_schema'] | null | undefined) => {
  const normalizedConfigSchema = normalizeContractConfigSchema(configSchema);
  const filteredProperties = Object.fromEntries(
    Object.entries(normalizedConfigSchema.properties).filter(([property]) => !EXCLUDED_CONFIG_VARS.includes(property)),
  );
  return {
    ...normalizedConfigSchema,
    properties: filteredProperties,
    required: normalizedConfigSchema.required.filter((property) => !EXCLUDED_CONFIG_VARS.includes(property)),
  };
};

/**
 * Compiles (or retrieves from cache) an AJV validator for a given schema.
 * The cacheKey must accurately reflect the exact shape of the schema (properties + required)
 * to avoid cache false positives.
 */
export const getOrCompileValidator = (cacheKey: string, jsonValidation: object): ValidateFunction => {
  let validate = validatorCache.get(cacheKey);
  if (!validate) {
    validate = ajv.compile(jsonValidation);
    validatorCache.set(cacheKey, validate);
  }
  return validate;
};

const ajv = new Ajv({ coerceTypes: true });
addFormats(ajv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);

const aesEncrypt = (text: string, key: Buffer, aesIv: Buffer) => {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, aesIv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(text, 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([ciphertext, tag]);
};

export const encryptValue = (rsaPublicKey: string, value: string) => {
  const aesKey = crypto.randomBytes(32);
  const aesIv = crypto.randomBytes(12);
  const aesEncryptedValueBuffer = aesEncrypt(value, aesKey, aesIv);

  const aesKeyAndIv = Buffer.concat([aesKey, aesIv]);
  const rsaEncryptedAesKeyAndIvBuffer = crypto.publicEncrypt(
    {
      key: rsaPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKeyAndIv,
  );

  const version = Buffer.from([0x02]);

  const concatenatedEncryptionBuffer = Buffer.concat([version, rsaEncryptedAesKeyAndIvBuffer, aesEncryptedValueBuffer]);
  return concatenatedEncryptionBuffer.toString('base64');
};

export const processPasswordConfigurationValue = (
  rawValue: string,
  publicKey: string,
) => {
  return encryptValue(publicKey, rawValue);
};

/**
 * Process a configuration value based on its schema type
 * Handles validation and encryption for passwords
 */
export const processConfigurationValue = (
  rawValue: string,
  propSchema: any,
  propKey: string,
): string => {
  // Validate based on type
  switch (propSchema.type) {
    case 'boolean':
      if (rawValue !== 'true' && rawValue !== 'false') {
        throw UnsupportedError(`Field "${propKey}" must be a boolean value (true or false). Received: "${rawValue}"`);
      }
      return rawValue;
    case 'integer': {
      const parsedInt = parseInt(rawValue, 10);
      if (Number.isNaN(parsedInt)) {
        throw UnsupportedError(`Field "${propKey}" must be a valid integer. Received: "${rawValue}"`);
      }
      return String(parsedInt);
    }
    case 'array':
      // Arrays are already joined as comma-separated strings by frontend
      return rawValue;
    default:
      return rawValue;
  }
};

/**
 * Convert a default value to string format for storage
 */
export const getDefaultValueAsString = (propSchema: any): string | null => {
  if (propSchema.default === undefined || propSchema.default === null) return null;

  switch (propSchema.type) {
    case 'array':
      return Array.isArray(propSchema.default)
        ? propSchema.default.join(',')
        : String(propSchema.default);
    case 'boolean':
    case 'integer':
      return String(propSchema.default);
    default:
      return typeof propSchema.default === 'string'
        ? propSchema.default
        : String(propSchema.default);
  }
};

/**
 * Resolve the final configuration value for a property
 */
export const resolveConfigurationValue = (
  propKey: string,
  propSchema: any,
  inputConfig: ContractConfigInput | undefined,
  existingConfig: ConnectorContractConfiguration | undefined,
  publicKey: string,
): ConnectorContractConfiguration | null => {
  const isPassword = propSchema.format === 'password';

  // No new value provided
  if (!inputConfig || !inputConfig.value || inputConfig.value === '') {
    // Keep existing password if available
    if (isPassword && existingConfig) {
      return existingConfig;
    }
    // Use default value if available
    const defaultValue = getDefaultValueAsString(propSchema);
    if (defaultValue !== null) {
      return { key: propKey, value: defaultValue };
    }
    return null;
  }

  // New value provided
  const rawValue = inputConfig.value;

  // Check if value unchanged (prevents re-encrypting passwords)
  if (rawValue === existingConfig?.value) {
    return existingConfig;
  }

  // Process new value
  if (isPassword) {
    const processedPasswordValue = processPasswordConfigurationValue(rawValue, publicKey);
    return {
      key: propKey,
      value: processedPasswordValue,
      encrypted: true,
    };
  }
  const processedValue = processConfigurationValue(
    rawValue,
    propSchema,
    propKey,
  );

  return {
    key: propKey,
    value: processedValue,
  };
};

/**
 * Format AJV validation errors into human-readable messages
 */
const formatValidationErrors = (errors: any[] | null | undefined, contractTitle: string): string => {
  if (!errors || errors.length === 0) {
    return `Invalid contract configuration for ${contractTitle}`;
  }

  const errorMessages = errors.map((error) => {
    const fieldPath = error.instancePath ? error.instancePath.replace(/^\//, '') : error.params?.missingProperty || 'unknown field';

    switch (error.keyword) {
      case 'required':
        return `Missing required field: "${error.params.missingProperty}"`;
      case 'type':
        return `Field "${fieldPath}" must be of type ${error.params.type} (received: ${typeof error.data})`;
      case 'enum':
        return `Field "${fieldPath}" must be one of: ${error.params.allowedValues?.join(', ') || 'allowed values'}`;
      case 'minLength':
        return `Field "${fieldPath}" must be at least ${error.params.limit} characters long`;
      case 'maxLength':
        return `Field "${fieldPath}" must not exceed ${error.params.limit} characters`;
      case 'minimum':
        return `Field "${fieldPath}" must be at least ${error.params.limit}`;
      case 'maximum':
        return `Field "${fieldPath}" must not exceed ${error.params.limit}`;
      case 'pattern':
        return `Field "${fieldPath}" does not match the required format`;
      case 'additionalProperties':
        return `Unknown field: "${error.params.additionalProperty}"`;
      default:
        return `Field "${fieldPath}": ${error.message}`;
    }
  });

  return `Invalid contract configuration for ${contractTitle}:\n${errorMessages.map((msg) => `  - ${msg}`).join('\n')}`;
};

export const validateContractConfigurations = (
  contractConfigurations: ConnectorContractConfiguration[],
  targetContract: Pick<CatalogContract, 'config_schema' | 'slug' | 'title'>,
) => {
  const targetConfig = getContractConfigSchemaWithoutExcludedRuntimeVars(targetContract.config_schema);

  // Build validation object from configurations
  // For AJV validation, arrays need to be actual arrays, not comma-separated strings
  type ContractConfigurationObject = Record<string, string | string[]>;
  const contractObject = contractConfigurations.reduce<ContractConfigurationObject>((acc, config) => {
    const propSchema = targetConfig.properties[config.key];
    if (propSchema && config.value !== undefined && config.value !== null) {
      // Convert comma-separated strings to arrays for AJV validation only
      if (propSchema.type === 'array' && typeof config.value === 'string') {
        acc[config.key] = config.value.split(',').map((v) => v.trim()).filter((v) => v !== '');
      } else {
        acc[config.key] = config.value;
      }
    }
    return acc;
  }, {});

  // Build validation properties - only include:
  // 1. Required fields (always needed for validation)
  // 2. Optional fields that are actually present in contractObject
  const validationProperties: Record<string, any> = {};
  const filteredRequired = targetConfig.required.filter((v) => v !== 'CONNECTOR_ID'); // FIXME: remove filter on CONNECTOR_ID when manifest is ok

  // Add required properties to the validation schema
  filteredRequired.forEach((key) => {
    if (targetConfig.properties[key]) {
      validationProperties[key] = targetConfig.properties[key];
    }
  });

  // Add optional properties ONLY if they are present in the actual configuration
  Object.keys(contractObject).forEach((key) => {
    if (!filteredRequired.includes(key) && targetConfig.properties[key]) {
      validationProperties[key] = targetConfig.properties[key];
    }
  });

  // Validate with AJV - it will handle type coercion and validation
  const jsonValidation = {
    type: targetConfig.type,
    properties: validationProperties,
    required: filteredRequired,
    additionalProperties: false,
  };

  // The key must exactly capture the shape of validationProperties, since it varies
  // depending on which optional fields are actually present in the request.
  const cacheKey = [
    targetContract.slug ?? targetContract.title,
    filteredRequired.slice().sort().join(','),
    Object.keys(validationProperties).sort().join(','),
  ].join('|');

  const validate = getOrCompileValidator(cacheKey, jsonValidation);
  logApp.debug('[OPENCTI-MODULE] Validating connector contract configuration', {
    module: 'catalog',
    contractSlug: targetContract.slug,
    contractTitle: targetContract.title,
    requiredCount: filteredRequired.length,
    providedCount: contractConfigurations.length,
    validatedFieldsCount: Object.keys(validationProperties).length,
  });
  const validContractObject = validate(contractObject);

  if (!validContractObject) {
    logApp.warn('[OPENCTI-MODULE] Invalid connector contract configuration', {
      module: 'catalog',
      contractSlug: targetContract.slug,
      contractTitle: targetContract.title,
      requiredCount: filteredRequired.length,
      providedCount: contractConfigurations.length,
      errorsCount: validate.errors?.length ?? 0,
    });
    const formattedError = formatValidationErrors(validate.errors, targetContract.title);
    throw UnsupportedError(formattedError, { errors: validate.errors });
  }
};

export const computeConnectorTargetContract = (
  configurations: ContractConfigInput[],
  targetContract: Pick<CatalogContract, 'config_schema' | 'slug' | 'title'>,
  publicKey: string,
  currentManagerContractConfiguration?: ConnectorContractConfiguration[],
): ConnectorContractConfiguration[] => {
  const targetConfig = getContractConfigSchemaWithoutExcludedRuntimeVars(targetContract.config_schema);
  let passwordCount = 0;
  let defaultedCount = 0;
  let reusedCount = 0;

  // Create maps for efficient lookups
  const configMap = new Map(configurations.map((c) => [c.key, c]));
  const currentConfigMap = new Map(
    currentManagerContractConfiguration?.map((c) => [c.key, c]) ?? [],
  );

  // Process each property and build configuration array
  const contractConfigurations: ConnectorContractConfiguration[] = [];

  Object.entries(targetConfig.properties).forEach(([propKey, propSchema]) => {
    const inputConfig = configMap.get(propKey);
    const existingConfig = currentConfigMap.get(propKey);
    const isPassword = propSchema.format === 'password';

    // Only process fields that are:
    // 1. Required (will use default if available)
    // 2. Have an input value provided
    // 3. Have an existing value (for passwords)
    const isRequired = targetConfig.required.includes(propKey);
    const hasInput = inputConfig && !isEmptyField(inputConfig.value);
    const hasExisting = existingConfig !== undefined;

    // Skip optional fields that have no value, no default, and are not required
    if (
      !isRequired
      && !hasInput
      && !hasExisting
      && (propSchema.default === undefined || propSchema.default === null)
    ) {
      return; // Skip this field entirely
    }

    if (!hasInput && !hasExisting && (propSchema.default !== undefined && propSchema.default !== null)) {
      defaultedCount += 1;
    }
    if (hasExisting && !hasInput) {
      reusedCount += 1;
    }
    if (isPassword && hasInput && inputConfig?.value !== existingConfig?.value) {
      passwordCount += 1;
    }

    const finalConfig = resolveConfigurationValue(
      propKey,
      propSchema,
      inputConfig,
      existingConfig,
      publicKey,
    );

    if (finalConfig) {
      contractConfigurations.push(finalConfig);
    }
  });

  // Validate the configurations
  validateContractConfigurations(contractConfigurations, targetContract);
  logApp.debug('[OPENCTI-MODULE] Computed connector contract configuration', {
    module: 'catalog',
    contractSlug: targetContract.slug,
    contractTitle: targetContract.title,
    inputCount: configurations.length,
    resolvedCount: contractConfigurations.length,
    passwordCount,
    defaultedCount,
    reusedCount,
  });

  return contractConfigurations;
};

const mapCatalogToGraphqlCatalog = (
  catalog: BasicStoreEntityCatalog,
  contracts: BasicStoreEntityCatalogContract[],
): GraphqlCatalog => {
  return {
    id: catalog.catalog_id,
    name: catalog.name,
    description: catalog.description,
    entity_type: catalog.entity_type,
    parent_types: catalog.parent_types,
    standard_id: catalog.standard_id,
    contracts: contracts.map((c) =>
      JSON.stringify(mapContractEntityFieldsToGraphqlCatalogContract(c, { excludeRuntimeConfigVars: true })),
    ),
  };
};

export const queryCatalogById = async (context: AuthContext, user: AuthUser, catalogId: string) => {
  const catalog = await findCatalogByCatalogId(context, user, catalogId);
  if (!catalog) {
    logApp.debug('[OPENCTI-MODULE] Catalog query by id returned no catalog', {
      module: 'catalog',
      catalogId,
    });
    return null;
  }
  const contracts = await findLatestCompatibleCatalogContractsByCatalogId(context, user, catalogId);
  logApp.debug('[OPENCTI-MODULE] Catalog query by id resolved', {
    module: 'catalog',
    catalogId,
    contractsCount: contracts.size,
  });
  return mapCatalogToGraphqlCatalog(catalog, [...contracts.values()]);
};

export const queryCatalogs = async (context: AuthContext, user: AuthUser) => {
  const catalogs = await findCatalogs(context, user);
  const contracts = await Promise.all(catalogs.map((catalog) => findLatestCompatibleCatalogContractsByCatalogId(context, user, catalog.catalog_id)));
  const contractsTotalCount = contracts.reduce((total, contractsByCatalog) => total + contractsByCatalog.size, 0);
  logApp.debug('[OPENCTI-MODULE] Catalogs query resolved', {
    module: 'catalog',
    catalogsCount: catalogs.length,
    contractsTotalCount,
  });
  const ret = catalogs.map((catalog, idx) => {
    return mapCatalogToGraphqlCatalog(catalog, [...contracts[idx].values()]);
  });
  return ret;
};

export const queryContractBySlug = async (context: AuthContext, user: AuthUser, contractSlug: string) => {
  const contract = await findLatestCompatibleCatalogContractBySlug(context, user, contractSlug);
  if (!contract) {
    logApp.debug('[OPENCTI-MODULE] Contract query by slug returned no contract', {
      module: 'catalog',
      contractSlug,
    });
    return null;
  }
  logApp.debug('[OPENCTI-MODULE] Contract query by slug resolved', {
    module: 'catalog',
    contractSlug,
    catalogId: contract.catalog_id,
    contractVersion: contract.contract_version,
  });
  return {
    catalog_id: contract.catalog_id,
    contract: JSON.stringify(mapContractEntityFieldsToGraphqlCatalogContract(contract, { excludeRuntimeConfigVars: true })),
  };
};

export const mapContractDtoV0ToContractEntityFields = (params: {
  catalogId: string;
  contractDto: CatalogContract;
  contractContentHash: string;
  logoUri: string | null;
}): CatalogContractEntityFields => {
  const { catalogId, contractDto, contractContentHash, logoUri } = params;
  const supportVersionValue = contractDto.support_version
    ? contractDto.support_version.replace(/^\s*>=\s*/, '').trim()
    : null;
  const normalizedSupportVersion = supportVersionValue && supportVersionValue.length > 0
    ? supportVersionValue
    : null;
  return {
    catalog_id: catalogId,
    contract_id: `${contractDto.slug}-${contractDto.container_version}`,
    content_hash: contractContentHash,
    title: contractDto.title,
    slug: contractDto.slug,
    description: contractDto.description,
    short_description: contractDto.short_description,
    logo_uri: logoUri ?? undefined,
    use_cases: contractDto.use_cases,
    verified: contractDto.verified,
    last_verified_date: contractDto.last_verified_date ?? undefined,
    playbook_supported: contractDto.playbook_supported,
    max_confidence_level: contractDto.max_confidence_level,
    support_version: normalizedSupportVersion ?? undefined,
    subscription_link: contractDto.subscription_link ?? undefined,
    source_code: contractDto.source_code ?? undefined,
    manager_supported: contractDto.manager_supported,
    contract_version: contractDto.container_version,
    image: contractDto.container_image,
    connector_type: contractDto.container_type,
    config_schema: contractDto.config_schema,
    license_type: contractDto.license_type ?? undefined,
    solution_categories: contractDto.solution_categories ?? undefined,
    contact: contractDto.contact ?? undefined,
  };
};

export const mapContractEntityFieldsToGraphqlCatalogContract = (
  contract: CatalogContractEntityFields,
  options: { excludeRuntimeConfigVars?: boolean } = {},
): GraphqlCatalogContract => {
  const { excludeRuntimeConfigVars = false } = options;
  const normalizedConfigSchema = normalizeContractConfigSchema(contract.config_schema);
  const configSchema = excludeRuntimeConfigVars
    ? getContractConfigSchemaWithoutExcludedRuntimeVars(normalizedConfigSchema)
    : normalizedConfigSchema;
  return {
    title: contract.title,
    slug: contract.slug,
    description: contract.description,
    short_description: contract.short_description,
    logo: contract.logo_uri ?? null,
    use_cases: contract.use_cases ?? [],
    verified: contract.verified,
    last_verified_date: contract.last_verified_date ?? '',
    playbook_supported: contract.playbook_supported,
    max_confidence_level: contract.max_confidence_level,
    support_version: contract.support_version ?? null,
    subscription_link: contract.subscription_link ?? null,
    source_code: contract.source_code ?? '',
    manager_supported: contract.manager_supported,
    container_version: contract.contract_version,
    container_image: contract.image,
    container_type: contract.connector_type,
    config_schema: configSchema,
    license_type: contract.license_type ?? null,
    solution_categories: contract.solution_categories ?? [],
    contact: contract.contact ?? null,
  };
};

export const mapContractEntityFieldsToEmbeddedConnectorManagerContract = (
  contract: CatalogContractEntityFields,
): CatalogContractEntityFields => {
  const {
    catalog_id,
    contract_id,
    content_hash,
    title,
    slug,
    description,
    short_description,
    logo_uri,
    use_cases,
    verified,
    last_verified_date,
    playbook_supported,
    max_confidence_level,
    support_version,
    subscription_link,
    source_code,
    manager_supported,
    contract_version,
    image,
    connector_type,
    config_schema,
    license_type,
    solution_categories,
    contact,
  } = contract;
  return {
    catalog_id,
    contract_id,
    content_hash,
    title,
    slug,
    description,
    short_description,
    logo_uri,
    use_cases,
    verified,
    last_verified_date,
    playbook_supported,
    max_confidence_level,
    support_version,
    subscription_link,
    source_code,
    manager_supported,
    contract_version,
    image,
    connector_type,
    config_schema,
    license_type,
    solution_categories,
    contact,
  };
};
