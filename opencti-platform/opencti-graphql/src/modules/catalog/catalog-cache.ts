import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { UnsupportedError } from '../../config/errors';
import { logApp } from '../../config/conf';
import type { CatalogContract, CatalogDefinition, CatalogType } from './catalog-types';

type InternalCatalog = {
  catalogMap: Record<string, CatalogType>;
  contractsByImage: Map<string, CatalogContract>;
};

const ajv = new Ajv({ coerceTypes: true });
addFormats(ajv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);
const schemaValidatorCache = new Map<string, ReturnType<typeof ajv.compile>>();

const isEmptyValue = (value: unknown) => value === null || value === undefined || value === '';

const getOrCompileCatalogSchemaValidator = (cacheKey: string, jsonValidation: object) => {
  let validate = schemaValidatorCache.get(cacheKey);
  if (!validate) {
    validate = ajv.compile(jsonValidation);
    schemaValidatorCache.set(cacheKey, validate);
  }
  return validate;
};

const sanitizeManagerConfigurationSchema = (contract: CatalogContract) => {
  if (!contract.manager_supported || !contract.config_schema) {
    return contract;
  }

  const finalContract = {
    ...contract,
    config_schema: {
      ...contract.config_schema,
      properties: { ...contract.config_schema.properties },
      required: [...contract.config_schema.required],
    },
  };

  const excludedConfigVars = ['OPENCTI_TOKEN', 'OPENCTI_URL', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE'];
  for (let i = 0; i < excludedConfigVars.length; i += 1) {
    delete finalContract.config_schema.properties[excludedConfigVars[i]];
  }
  finalContract.config_schema.required = finalContract.config_schema.required
    .filter((item) => !excludedConfigVars.includes(item));

  return finalContract;
};

const validateManagerSupportedContract = (catalogId: string, contract: CatalogContract) => {
  if (!contract.manager_supported) return;

  if (!contract.config_schema) {
    logApp.warn('A contract has manager_supported=true but is missing config_schema', { contractTitle: contract.title });
    return;
  }

  if (isEmptyValue(contract.container_image)) {
    throw UnsupportedError('Contract must define container_image field', { contractTitle: contract.title });
  }
  if (isEmptyValue(contract.container_type)) {
    throw UnsupportedError('Contract must define container_type field', { contractTitle: contract.title });
  }

  const jsonValidation = {
    type: contract.config_schema.type,
    properties: contract.config_schema.properties,
    required: contract.config_schema.required,
    additionalProperties: contract.config_schema.additionalProperties,
  };

  try {
    getOrCompileCatalogSchemaValidator(`catalog-contract:${catalogId}:${contract.slug}`, jsonValidation);
  } catch (err) {
    throw UnsupportedError('Contract must be a valid json schema definition', { cause: err });
  }
};

export const clearCatalogCacheValidators = () => {
  schemaValidatorCache.clear();
};

export const buildCatalogMapFromDefinitions = (catalogDefinitions: CatalogDefinition[]): Record<string, CatalogType> => {
  const catalogMap: Record<string, CatalogType> = {};

  for (let index = 0; index < catalogDefinitions.length; index += 1) {
    const catalog = catalogDefinitions[index];

    for (let contractIndex = 0; contractIndex < catalog.contracts.length; contractIndex += 1) {
      validateManagerSupportedContract(catalog.id, catalog.contracts[contractIndex]);
    }

    catalogMap[catalog.id] = {
      definition: catalog,
      graphql: {
        id: catalog.id,
        entity_type: 'Catalog',
        parent_types: ['Internal'],
        standard_id: `catalog--${catalog.id}`,
        name: catalog.name,
        description: catalog.description,
        contracts: catalog.contracts.map((contract) => JSON.stringify(sanitizeManagerConfigurationSchema(contract))),
      },
    };
  }

  return catalogMap;
};

export const buildContractsByImageCache = (catalogMap: Record<string, CatalogType>): Map<string, CatalogContract> => {
  const contracts = Object.values(catalogMap)
    .map((catalog) => catalog.definition.contracts.map((contract) => sanitizeManagerConfigurationSchema(contract)))
    .flat();
  return new Map(contracts.map((contract) => [contract.container_image, contract]));
};

export const buildInternalCatalog = (catalogDefinitions: CatalogDefinition[]): InternalCatalog => {
  const catalogMap = buildCatalogMapFromDefinitions(catalogDefinitions);
  const contractsByImage = buildContractsByImageCache(catalogMap);
  return { catalogMap, contractsByImage };
};

export type { InternalCatalog };
