import fs from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as R from 'ramda';
import crypto from 'crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { type CatalogContract, type CatalogDefinition, type CatalogType } from './catalog-types';
import { isEmptyField } from '../../database/utils';
import { UnsupportedError } from '../../config/errors';
import { idGenFromData } from '../../schema/identifier';
import filigranCatalog from './filigran/opencti-manifest.json';
import conf from '../../config/conf';

const CUSTOM_CATALOGS: string[] = conf.get('app:custom_catalogs') ?? [];
const ajv = new Ajv({ coerceTypes: true });
addFormats(ajv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);

// Cache of catalog to read on disk and parse only once
let catalogMap: Record<string, CatalogType>;
const getCatalogs = () => {
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
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    buffer
  );
  return encrypted.toString('base64');
};

export const computeConnectorTargetContract = (configurations: any, targetContract: CatalogContract, publicKey: string) => {
  const targetConfig = targetContract.config_schema;
  // Rework configuration for default an array support
  const contractConfigurations = [];
  const keys = Object.keys(targetConfig.properties);
  for (let i = 0; i < keys.length; i += 1) {
    const propKey = keys[i];
    const currentConfig: any = configurations.find((config: any) => config.key === propKey);

    if (!currentConfig) {
      if (targetConfig.properties[propKey].default) {
        contractConfigurations.push(({ key: propKey, value: targetConfig.properties[propKey].default }));
      }
    } else if (targetConfig.properties[propKey].type !== 'array') {
      const rawValue = currentConfig.value[0];
      const isPassword = targetConfig.properties[propKey].format === 'password';
      const finalValue = isPassword ? encryptValue(publicKey, rawValue) : rawValue;
      contractConfigurations.push({
        key: propKey,
        value: finalValue,
        ...(isPassword && { encrypted: true }),
      });
    } else {
      contractConfigurations.push(currentConfig);
    }
  }
  // Build the json contract
  const contractObject: any = R.mergeAll(contractConfigurations.map((config: any) => ({ [config.key]: config.value })));
  // Validate the contract
  const jsonValidation = {
    type: targetConfig.type,
    properties: targetConfig.properties,
    required: targetConfig.required,
    additionalProperties: targetConfig.additionalProperties
  };
  const validate = ajv.compile(jsonValidation);
  const validContractObject = validate(contractObject);
  if (!validContractObject) {
    throw UnsupportedError(`Invalid contract definition for ${targetContract.title}`, { errors: validate.errors });
  }
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

export const findAll = (_context: AuthContext, _user: AuthUser) => {
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
