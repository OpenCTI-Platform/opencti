import fs from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import crypto from 'crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { type CatalogContract, type CatalogDefinition, type CatalogType } from './catalog-types';
import { isEmptyField } from '../../database/utils';
import { UnsupportedError } from '../../config/errors';
import { idGenFromData } from '../../schema/identifier';
import filigranCatalog from '../../__generated__/opencti-manifest.json';
import conf, { isFeatureEnabled, logApp } from '../../config/conf';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../generated/graphql';

const CUSTOM_CATALOGS: string[] = conf.get('app:custom_catalogs') ?? [];
const ajv = new Ajv({ coerceTypes: true });
addFormats(ajv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);

// Cache of catalog to read on disk and parse only once
let catalogMap: Record<string, CatalogType>;
const getCatalogs = (): Record<string, CatalogType> => {
  // TEMPORARY HACK: Live catalog mode for local development with custom catalogs only
  // This feature allows loading catalogs without cache for testing purposes
  // TODO: Remove this hack when proper catalog management is implemented
  const shouldUseLiveCatalogs = isFeatureEnabled('LIVE_CATALOGS') && CUSTOM_CATALOGS.length > 0;

  if (shouldUseLiveCatalogs) {
    // Live mode: no cache, only custom catalogs (excluding filigran catalog)
    const liveCatalogMap: Record<string, CatalogType> = {};
    const catalogs = CUSTOM_CATALOGS.map((custom) => fs.readFileSync(custom, { encoding: 'utf8', flag: 'r' }));
    // Note: intentionally NOT adding filigranCatalog here

    for (let index = 0; index < catalogs.length; index += 1) {
      const catalogRaw = catalogs[index];
      const catalog = JSON.parse(catalogRaw) as CatalogDefinition;
      // Validate each contract
      for (let contractIndex = 0; contractIndex < catalog.contracts.length; contractIndex += 1) {
        const contract = catalog.contracts[contractIndex];
        if (contract.manager_supported) {
          if (isEmptyField(contract.container_image)) {
            throw UnsupportedError('Contract must defined container_image field');
          }
          if (isEmptyField(contract.container_type)) {
            throw UnsupportedError('Contract must defined container_type field');
          }

          if (contract.config_schema) {
            const jsonValidation = {
              type: contract.config_schema.type,
              properties: contract.config_schema.properties,
              required: contract.config_schema.required,
              additionalProperties: contract.config_schema.additionalProperties
            };
            try {
              ajv.compile(jsonValidation);
            } catch (err) {
              throw UnsupportedError('Contract must be a valid json schema definition', { cause: err });
            }
          }
        }
      }
      liveCatalogMap[catalog.id] = {
        definition: catalog,
        graphql: {
          id: catalog.id,
          entity_type: 'Catalog',
          parent_types: ['Internal'],
          standard_id: idGenFromData('catalog', { id: catalog.id }),
          name: catalog.name,
          description: catalog.description,
          contracts: catalog.contracts.map((c) => {
            const finalContract = c;
            if (finalContract.manager_supported) {
              const EXCLUDED_CONFIG_VARS = ['OPENCTI_TOKEN', 'OPENCTI_URL', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE'];
              EXCLUDED_CONFIG_VARS.forEach((property) => {
                delete finalContract.config_schema.properties[property];
              });
              finalContract.config_schema.required = c.config_schema.required.filter((item) => !EXCLUDED_CONFIG_VARS.includes(item));
            }
            return JSON.stringify(finalContract);
          })
        }
      };
    }
    return liveCatalogMap;
  }
  // END OF TEMPORARY HACK

  // Original code unchanged below
  if (!catalogMap) {
    catalogMap = {};

    const catalogs = CUSTOM_CATALOGS.map((custom) => fs.readFileSync(custom, { encoding: 'utf8', flag: 'r' }));
    catalogs.push(JSON.stringify(filigranCatalog));
    for (let index = 0; index < catalogs.length; index += 1) {
      const catalogRaw = catalogs[index];
      const catalog = JSON.parse(catalogRaw) as CatalogDefinition;
      // Validate each contract
      for (let contractIndex = 0; contractIndex < catalog.contracts.length; contractIndex += 1) {
        const contract = catalog.contracts[contractIndex];
        if (contract.manager_supported) {
          if (!contract.config_schema) {
            logApp.warn('A contract has manager_supported=true but is missing config_schema', { contractTitle: contract.title });
          } else {
            if (isEmptyField(contract.container_image)) {
              throw UnsupportedError('Contract must defined container_image field');
            }
            if (isEmptyField(contract.container_type)) {
              throw UnsupportedError('Contract must defined container_type field');
            }

            if (contract.config_schema) {
              const jsonValidation = {
                type: contract.config_schema.type,
                properties: contract.config_schema.properties,
                required: contract.config_schema.required,
                additionalProperties: contract.config_schema.additionalProperties
              };
              try {
                ajv.compile(jsonValidation);
              } catch (err) {
                throw UnsupportedError('Contract must be a valid json schema definition', { cause: err });
              }
            }
          }
        }
      }
      catalogMap[catalog.id] = {
        definition: catalog,
        graphql: {
          id: catalog.id,
          entity_type: 'Catalog',
          parent_types: ['Internal'],
          standard_id: idGenFromData('catalog', { id: catalog.id }),
          name: catalog.name,
          description: catalog.description,
          contracts: catalog.contracts.map((c) => {
            const finalContract = c;
            if (finalContract.manager_supported) {
              if (!finalContract.config_schema) {
                logApp.warn('A contract has manager_supported=true but is missing config_schema', { contractTitle: finalContract.title });
              } else {
                const EXCLUDED_CONFIG_VARS = ['OPENCTI_TOKEN', 'OPENCTI_URL', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE'];
                EXCLUDED_CONFIG_VARS.forEach((property) => {
                  delete finalContract.config_schema.properties[property];
                });
                finalContract.config_schema.required = c.config_schema.required.filter((item) => !EXCLUDED_CONFIG_VARS.includes(item));
              }
            }
            return JSON.stringify(finalContract);
          })
        }
      };
    }
  }
  return catalogMap;
};

const aesEncrypt = (text: string, key: Buffer, aesIv: Buffer) => {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, aesIv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
};

const encryptValue = (rsaPublicKey: string, value: string) => {
  const aesKey = crypto.randomBytes(32);
  const aesIv = crypto.randomBytes(16);
  const aesEncryptedValue = aesEncrypt(value, aesKey, aesIv);

  const rsaEncryptedAesKeyBuffer = crypto.publicEncrypt(
    {
      key: rsaPublicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    aesKey
  );
  const rsaEncryptedAesKey = rsaEncryptedAesKeyBuffer.toString('base64');

  const rsaEncryptedAesIvBuffer = crypto.publicEncrypt(
    {
      key: rsaPublicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    aesIv
  );
  const rsaEncryptedAesIv = rsaEncryptedAesIvBuffer.toString('base64');

  return { value: aesEncryptedValue, key: rsaEncryptedAesKey, iv: rsaEncryptedAesIv };
};

export const processPasswordConfigurationValue = (
  rawValue: string,
  publicKey: string
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
  publicKey: string
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
      value: processedPasswordValue.value,
      encrypted: true,
      encryptionKey: processedPasswordValue.key,
      encryptionIv: processedPasswordValue.iv
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
  targetContract: CatalogContract
) => {
  const targetConfig = targetContract.config_schema;

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
    additionalProperties: false
  };

  const validate = ajv.compile(jsonValidation);
  const validContractObject = validate(contractObject);

  if (!validContractObject) {
    const formattedError = formatValidationErrors(validate.errors, targetContract.title);
    throw UnsupportedError(formattedError, { errors: validate.errors });
  }
};

export const computeConnectorTargetContract = (
  configurations: ContractConfigInput[],
  targetContract: CatalogContract,
  publicKey: string,
  currentManagerContractConfiguration?: ConnectorContractConfiguration[]
): ConnectorContractConfiguration[] => {
  const targetConfig = targetContract.config_schema;

  // Create maps for efficient lookups
  const configMap = new Map(configurations.map((c) => [c.key, c]));
  const currentConfigMap = new Map(
    currentManagerContractConfiguration?.map((c) => [c.key, c]) ?? []
  );

  // Process each property and build configuration array
  const contractConfigurations: ConnectorContractConfiguration[] = [];

  Object.entries(targetConfig.properties).forEach(([propKey, propSchema]) => {
    const inputConfig = configMap.get(propKey);
    const existingConfig = currentConfigMap.get(propKey);

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

    const finalConfig = resolveConfigurationValue(
      propKey,
      propSchema,
      inputConfig,
      existingConfig,
      publicKey
    );

    if (finalConfig) {
      contractConfigurations.push(finalConfig);
    }
  });

  // Validate the configurations
  validateContractConfigurations(contractConfigurations, targetContract);

  return contractConfigurations;
};

export const getSupportedContractsByImage = () => {
  const catalogDefinitions = getCatalogs();
  const contracts = Object.values(catalogDefinitions).map((catalog) => catalog.definition.contracts).flat();
  return new Map(contracts.map((contract) => [contract.container_image, contract]));
};

export const findById = (_context: AuthContext, _user: AuthUser, catalogId: string) => {
  const catalogDefinitions = getCatalogs();
  return catalogDefinitions[catalogId].graphql;
};

export const findCatalog = (_context: AuthContext, _user: AuthUser) => {
  const catalogDefinitions = getCatalogs();
  return Object.values(catalogDefinitions).map((catalog) => catalog.graphql);
};

export const findContractBySlug = (_context: AuthContext, _user: AuthUser, contractSlug: string) => {
  const catalogDefinitions = getCatalogs();
  if (!catalogDefinitions) {
    return null;
  }
  const catalogs = Object.values(catalogDefinitions).map((catalog) => catalog.graphql);
  const foundContract = catalogs
    .map((catalog) => {
      const contract = catalog.contracts.find((contractStr) => JSON.parse(contractStr).slug === contractSlug);
      return contract ? { catalog_id: catalog.id, contract } : null;
    })
    .find((contract) => contract !== null);
  return foundContract || null;
};
