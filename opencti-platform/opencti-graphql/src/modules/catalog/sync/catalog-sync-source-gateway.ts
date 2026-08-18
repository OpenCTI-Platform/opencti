import { readFile } from 'node:fs/promises';
import type { CatalogContract, CatalogDefinition, TypedProperty } from '../catalog-types';
import type { CatalogContractSyncSource, CatalogSyncSource, CatalogSyncSourceConfig } from './catalog-sync-types';
import conf, { logApp } from '../../../config/conf';
import { isEmptyField } from '../../../database/utils';
import { UnsupportedError } from '../../../config/errors';
import { getOrCompileValidator } from '../catalog-domain';
import { getHttpClient } from '../../../utils/http-client';

type CatalogContractDtoV0 = CatalogContract;
type CatalogDtoV0 = CatalogDefinition;
type CatalogContractDtoV1 = {
  id: string;
  title: string;
  slug: string;
  description: string;
  short_description: string;
  logo: string | null;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string;
  subscription_link: string | null;
  source_code: string | null;
  manager_supported: boolean;
  support_version: string | null;
  license_type: 'Free' | 'Commercial' | null;
  contact: string | null;
  solution_categories: string[];
  version: string | null;
  image_name: string | null;
  image_type: string;
  additional_properties: Record<string, unknown>;
  config_schema: Record<string, unknown>;
};
type CatalogDtoV1 = {
  id: string;
  name: string;
  description: string;
  manifest_schema_version: '1';
  manifest_version: string;
  product_version: string;
  contracts: Array<CatalogContractDtoV1>;
};

interface CatalogSyncSourceAdapter {
  fetch: () => Promise<CatalogDtoV0 | CatalogDtoV1>;
  fetchRevisionHint?: () => Promise<string | undefined>;
}

const DEFAULT_REMOTE_CATALOG_TIMEOUT_MS = 30000;
const resolveRemoteCatalogTimeoutMs = () => {
  const configuredTimeout = Number(conf.get('app:catalog_sync_remote_timeout') ?? conf.get('app:request_timeout'));
  if (!Number.isFinite(configuredTimeout) || configuredTimeout <= 0) {
    return DEFAULT_REMOTE_CATALOG_TIMEOUT_MS;
  }
  return configuredTimeout;
};

const withAbortTimeout = async <T>(timeoutMs: number, call: (signal: AbortSignal) => Promise<T>): Promise<T> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await call(controller.signal);
  } finally {
    clearTimeout(timer);
  }
};

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

class RemoteCatalogSyncSource implements CatalogSyncSourceAdapter {
  constructor(private sourceConfig: Extract<CatalogSyncSourceConfig, { kind: 'remote' }>) {}

  async fetch() {
    const timeout = resolveRemoteCatalogTimeoutMs();
    const client = getHttpClient({ responseType: 'text', timeout });
    const response = await withAbortTimeout(timeout, (signal) => client.get(this.sourceConfig.uri, { signal }));
    return JSON.parse(response.data);
  }

  async fetchRevisionHint() {
    const timeout = resolveRemoteCatalogTimeoutMs();
    const client = getHttpClient({ responseType: 'text', timeout });
    const response = await withAbortTimeout(timeout, (signal) => client.head(this.sourceConfig.uri, { signal }));
    const etagHeader = response.headers?.etag;
    const etag = Array.isArray(etagHeader) ? etagHeader[0] : etagHeader;
    if (!etag || typeof etag !== 'string') {
      return undefined;
    }
    return etag;
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
    case 'remote': {
      return new RemoteCatalogSyncSource(config);
    }
    default:
      throw UnsupportedError(`Unknown catalog sync source kind (${JSON.stringify(config)})`);
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

const DEFAULT_CONFIG_SCHEMA: CatalogContractDtoV0['config_schema'] = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: '',
  type: 'object',
  properties: {},
  required: [],
  additionalProperties: true,
};

const normalizeConfigSchema = (configSchema: unknown): CatalogContractDtoV0['config_schema'] => {
  if (!configSchema || typeof configSchema !== 'object' || Array.isArray(configSchema)) {
    return DEFAULT_CONFIG_SCHEMA;
  }
  const schema = configSchema as Record<string, unknown>;
  return {
    $schema: typeof schema.$schema === 'string' ? schema.$schema : DEFAULT_CONFIG_SCHEMA.$schema,
    $id: typeof schema.$id === 'string' ? schema.$id : DEFAULT_CONFIG_SCHEMA.$id,
    type: typeof schema.type === 'string' ? schema.type : DEFAULT_CONFIG_SCHEMA.type,
    properties: schema.properties && typeof schema.properties === 'object' && !Array.isArray(schema.properties)
      ? schema.properties as Record<string, TypedProperty>
      : DEFAULT_CONFIG_SCHEMA.properties,
    required: Array.isArray(schema.required)
      ? schema.required.filter((item): item is string => typeof item === 'string')
      : DEFAULT_CONFIG_SCHEMA.required,
    additionalProperties: typeof schema.additionalProperties === 'boolean'
      ? schema.additionalProperties
      : DEFAULT_CONFIG_SCHEMA.additionalProperties,
  };
};

const normalizeSupportVersion = (supportVersion: string | null | undefined): string | null => {
  if (!supportVersion) {
    return null;
  }
  const normalized = supportVersion.replace(/^\s*>=\s*/, '').trim();
  return normalized.length > 0 ? normalized : null;
};

const mapCatalogContractDtoV1ToCatalogContractDtoV0 = (contractDto: CatalogContractDtoV1): CatalogContractDtoV0 => {
  return {
    title: contractDto.title,
    slug: contractDto.slug,
    description: contractDto.description,
    short_description: contractDto.short_description,
    logo: contractDto.logo,
    use_cases: contractDto.use_cases,
    verified: contractDto.verified,
    last_verified_date: contractDto.last_verified_date,
    playbook_supported: false,
    max_confidence_level: 100,
    support_version: normalizeSupportVersion(contractDto.support_version),
    subscription_link: contractDto.subscription_link,
    source_code: contractDto.source_code ?? '',
    manager_supported: contractDto.manager_supported,
    container_version: contractDto.version ?? '',
    container_image: contractDto.image_name ?? '',
    container_type: contractDto.image_type,
    config_schema: normalizeConfigSchema(contractDto.config_schema),
    license_type: contractDto.license_type,
    solution_categories: contractDto.solution_categories,
    contact: contractDto.contact,
  };
};

const isCatalogDtoV1 = (catalog: CatalogDtoV0 | CatalogDtoV1): catalog is CatalogDtoV1 => {
  return typeof (catalog as CatalogDtoV1).manifest_schema_version === 'string';
};

export const mapCatalogContractDtoToCatalogContractSyncSource = (
  contractDto: CatalogContractDtoV0,
): CatalogContractSyncSource => {
  const normalizedSupportVersion = normalizeSupportVersion(contractDto.support_version);
  return {
    id: `${contractDto.slug}-${contractDto.container_version}`,
    ...contractDto,
    support_version: normalizedSupportVersion,
  };
};

export const mapCatalogDtoToCatalogSyncSource = (catalog: CatalogDtoV0 | CatalogDtoV1) => {
  if (isCatalogDtoV1(catalog)) {
    return {
      id: catalog.id,
      name: catalog.name,
      description: catalog.description,
      version: catalog.product_version,
      contracts: catalog.contracts.map((contractDto) => {
        const normalizedContractDto = mapCatalogContractDtoV1ToCatalogContractDtoV0(contractDto);
        return {
          id: contractDto.id,
          ...normalizedContractDto,
        };
      }),
    };
  }
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

export const fetchSourceCatalogRevisionHint = async (sourceConfig: CatalogSyncSourceConfig): Promise<string | undefined> => {
  const adapter = getCatalogSourceAdapter(sourceConfig);
  return adapter.fetchRevisionHint?.();
};
