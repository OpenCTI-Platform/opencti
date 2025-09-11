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
import conf, { isFeatureEnabled } from '../../config/conf';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../generated/graphql';

const CUSTOM_CATALOGS: string[] = conf.get('app:custom_catalogs') ?? [];
const ajv = new Ajv({ coerceTypes: true });
addFormats(ajv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);

// Cache of catalog to read on disk and parse only once
let catalogMap: Record<string, CatalogType>;
const getCatalogs = () => {
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
  }
  return catalogMap;
};

const encryptValue = (publicKey: string, value: string) => {
  const buffer = Buffer.from(value, 'utf8');
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    buffer
  );
  return encrypted.toString('base64');
};

/**
 * Process a configuration value based on its schema type
 * Handles validation and encryption for passwords
 */
export const processConfigurationValue = (
  rawValue: string,
  propSchema: any,
  propKey: string,
  isPassword: boolean,
  publicKey: string
): string => {
  if (isPassword) {
    return encryptValue(publicKey, rawValue);
  }

  // Validate based on type
  switch (propSchema.type) {
    case 'boolean':
      if (rawValue !== 'true' && rawValue !== 'false') {
        throw UnsupportedError(`Invalid boolean value for ${propKey}: ${rawValue}`);
      }
      return rawValue;
    case 'integer': {
      const parsedInt = parseInt(rawValue, 10);
      if (Number.isNaN(parsedInt)) {
        throw UnsupportedError(`Invalid integer value for ${propKey}: ${rawValue}`);
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
  if (propSchema.default === undefined) return null;

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
  if (!inputConfig || !inputConfig.value) {
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
  const processedValue = processConfigurationValue(
    rawValue,
    propSchema,
    propKey,
    isPassword,
    publicKey
  );

  return {
    key: propKey,
    value: processedValue,
    ...(isPassword && { encrypted: true }),
  };
};

export const validateContractConfigurations = (
  contractConfigurations: ConnectorContractConfiguration[],
  targetContract: CatalogContract
) => {
  const targetConfig = targetContract.config_schema;

  // Build validation object from configurations
  type ContractConfigurationObject = Record<string, string>;
  const contractObject = contractConfigurations.reduce<ContractConfigurationObject>((acc, config) => {
    const propSchema = targetConfig.properties[config.key];
    if (propSchema && config.value !== undefined && config.value !== null) {
      acc[config.key] = config.value;
    }
    return acc;
  }, {});

  // Validate with AJV - it will handle type coercion and validation
  const jsonValidation = {
    type: targetConfig.type,
    properties: targetConfig.properties,
    // required: targetConfig.required,
    required: targetConfig.required.filter((v) => v !== 'CONNECTOR_ID'), // FIXME: remove filter on CONNECTOR_ID when manifest is ok
    additionalProperties: targetConfig.additionalProperties
  };

  const validate = ajv.compile(jsonValidation);
  const validContractObject = validate(contractObject);

  if (!validContractObject) {
    throw UnsupportedError(`Invalid contract configuration for ${targetContract.title}`, { errors: validate.errors });
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
  const catalogs = Object.values(catalogDefinitions).map((catalog) => catalog.graphql);
  return catalogs
    .map((catalog) => {
      const contract = catalog.contracts.find((contractStr) => JSON.parse(contractStr).slug === contractSlug);
      return contract ? { catalog_id: catalog.id, contract } : null;
    })
    .find((result) => result !== null);
};
