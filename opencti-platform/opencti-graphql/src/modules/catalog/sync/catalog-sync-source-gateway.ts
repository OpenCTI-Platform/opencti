import { readFile } from 'node:fs/promises';
import type { CatalogContractDtoV0, CatalogDefinition, CatalogDtoV0 } from '../catalog-types';
import type { CatalogContractSyncSource, CatalogSyncSource, CatalogSyncSourceConfig } from './catalog-sync-types';
import { logApp } from '../../../config/conf';
import { isEmptyField } from '../../../database/utils';
import { UnsupportedError } from '../../../config/errors';
import { getOrCompileValidator } from '../catalog-domain';

interface CatalogSyncSourceAdapter {
  fetch: () => Promise<CatalogDtoV0>;
}

class EmbeddedCatalogSyncSource implements CatalogSyncSourceAdapter {
  constructor(private _sourceConfig: Extract<CatalogSyncSourceConfig, { kind: 'embedded' }>) {}

  async fetch() {
    const data = await import('../../../__generated__/opencti-manifest.json');
    return data.default as unknown as CatalogDefinition;
  }
}

class LocalCatalogSyncSource implements CatalogSyncSourceAdapter {
  constructor(private sourceConfig: Extract<CatalogSyncSourceConfig, { kind: 'local' }>) {}

  async fetch() {
    const catalog = await readFile(this.sourceConfig.filepath, { encoding: 'utf8', flag: 'r' });
    return JSON.parse(catalog);
  }
}

const getCatalogSourceAdapter = (config: CatalogSyncSourceConfig): CatalogSyncSourceAdapter => {
  switch (config.kind) {
    case 'local': {
      return new LocalCatalogSyncSource(config);
    }
    case 'embedded': {
      return new EmbeddedCatalogSyncSource(config);
    }
    default:
      throw new Error(`Unknown catalog sync source kind (${JSON.stringify(config)})`);
  };
};

const validateSyncSource = (syncSource: CatalogSyncSource) => {
  // Validate each contract
  for (let contractIndex = 0; contractIndex < syncSource.contracts.length; contractIndex += 1) {
    const contract = syncSource.contracts[contractIndex];
    if (contract.manager_supported) {
      if (!contract.config_schema) {
        logApp.warn('A contract has manager_supported=true but is missing config_schema', { contractTitle: contract.title });
      } else {
        if (isEmptyField(contract.container_image)) {
          throw UnsupportedError('Contract must define container_image field', { contractTitle: contract.title });
        }
        if (isEmptyField(contract.container_type)) {
          throw UnsupportedError('Contract must define container_type field', { contractTitle: contract.title });
        }

        if (contract.config_schema) {
          const jsonValidation = {
            type: contract.config_schema.type,
            properties: contract.config_schema.properties,
            required: contract.config_schema.required,
            additionalProperties: contract.config_schema.additionalProperties,
          };
          try {
            getOrCompileValidator(`catalog-contract:${syncSource.id}:${contract.slug}`, jsonValidation);
          } catch (err) {
            throw UnsupportedError('Contract must be a valid json schema definition', { cause: err });
          }
        }
      }
    }
  }
};

export const mapCatalogContractDtoToCatalogContractSyncSource = (
  contractDto: CatalogContractDtoV0,
): CatalogContractSyncSource => {
  return {
    id: `${contractDto.slug}-${contractDto.container_version}`,
    ...contractDto,
  };
};

export const mapCatalogDtoToCatalogSyncSource = (catalog: CatalogDtoV0) => {
  const syncSource = {
    ...catalog,
    contracts: catalog.contracts.map(mapCatalogContractDtoToCatalogContractSyncSource),
  };
  return syncSource;
};

export const fetchSourceCatalog = async (sourceConfig: CatalogSyncSourceConfig): Promise<CatalogSyncSource> => {
  const adapter = getCatalogSourceAdapter(sourceConfig);
  const raw = await adapter.fetch();
  const syncSource = mapCatalogDtoToCatalogSyncSource(raw);
  validateSyncSource(syncSource);
  return syncSource;
};
