import { readFile } from 'node:fs/promises';
import path from 'node:path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import type { ValidateFunction } from 'ajv';
import conf, { PLATFORM_VERSION, logApp } from '../../config/conf';
import type { CatalogContract, CatalogDefinition, IngestionConnectorType } from './catalog-types';
import { UnsupportedError } from '../../config/errors';
import { sanitizeManagerConfigSchema } from './catalog-config-schema';
import { validateManagerSupportedContract } from './catalog-contract-validation';

export type CatalogSourceConfig = {
  kind: 'remote' | 'local';
  uri: string;
};

export type CatalogResolutionConfig = {
  source: CatalogSourceConfig;
  originalUri: string;
};

export type RawManifest = unknown;

export type PersistableManifestMetadata = {
  catalogId: string;
  manifestVersion?: string;
  productVersion?: string;
};

export interface CatalogSourceAdapter {
  fetch(source: CatalogSourceConfig, options?: { signal?: AbortSignal }): Promise<RawManifest>;
}

const CATALOG_PRODUCT = 'opencti';
const CATALOG_INTEGRATION_TYPE = 'connector';

const buildDefaultRemoteCatalogUri = (xtmHubUrl: string) => {
  const normalizedBaseUrl = xtmHubUrl.replace(/\/+$/, '');
  return `${normalizedBaseUrl}/${CATALOG_PRODUCT}/${PLATFORM_VERSION}/${CATALOG_INTEGRATION_TYPE}/manifests/latest`;
};

const isHttpUri = (value: string) => value.startsWith('http://') || value.startsWith('https://');

export const resolveCatalogSource = (uri?: string | null): CatalogResolutionConfig => {
  const configuredUri = uri?.trim();

  if (!configuredUri) {
    const xtmHubUrl = conf.get('xtm:xtmhub_url');
    const remoteUri = buildDefaultRemoteCatalogUri(xtmHubUrl);
    return {
      source: { kind: 'remote', uri: remoteUri },
      originalUri: remoteUri,
    };
  }

  if (isHttpUri(configuredUri)) {
    return {
      source: { kind: 'remote', uri: configuredUri },
      originalUri: configuredUri,
    };
  }

  if (configuredUri.includes('://') && !configuredUri.startsWith('file://')) {
    throw UnsupportedError(`Unsupported catalog source URI scheme: ${configuredUri}`);
  }

  const withoutFilePrefix = configuredUri.startsWith('file://')
    ? configuredUri.slice('file://'.length)
    : configuredUri;
  const localPath = path.isAbsolute(withoutFilePrefix)
    ? withoutFilePrefix
    : path.resolve(process.cwd(), withoutFilePrefix);

  return {
    source: { kind: 'local', uri: localPath },
    originalUri: configuredUri,
  };
};

const toBoolean = (value: unknown, defaultValue = false) => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true';
  return defaultValue;
};

const toNumber = (value: unknown, defaultValue: number) => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return defaultValue;
};

const toStringArray = (value: unknown) => (Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : []);

const defaultConfigSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://filigran.io/opencti/catalog/default_config.schema.json',
  type: 'object',
  properties: {},
  required: [],
  additionalProperties: true,
} as CatalogContract['config_schema'];

const adapterValidatorCache = new Map<string, ValidateFunction>();
const adapterAjv = new Ajv({ coerceTypes: true });
addFormats(adapterAjv, ['password', 'uri', 'duration', 'email', 'date-time', 'date']);

const getOrCompileAdapterValidator = (cacheKey: string, jsonValidation: object): ValidateFunction => {
  let validate = adapterValidatorCache.get(cacheKey);
  if (!validate) {
    validate = adapterAjv.compile(jsonValidation);
    adapterValidatorCache.set(cacheKey, validate);
  }
  return validate;
};

const sanitizeNewManifestConfigSchema = (schema: Record<string, any>) => {
  const sanitizedSchema = sanitizeManagerConfigSchema(schema);

  const properties = { ...(sanitizedSchema.properties ?? {}) };
  const required = Array.isArray(sanitizedSchema.required) ? [...sanitizedSchema.required] : [];

  return {
    ...defaultConfigSchema,
    ...sanitizedSchema,
    properties,
    required,
    additionalProperties: schema?.additionalProperties ?? true,
  };
};

const normalizeContractFromNewManifest = (contract: Record<string, any>): CatalogContract => {
  const additional = (contract.additional_properties ?? {}) as Record<string, any>;
  const schema = contract.config_schema ?? defaultConfigSchema;

  return {
    title: contract.title ?? '',
    slug: contract.slug ?? '',
    description: contract.description ?? '',
    short_description: contract.short_description ?? '',
    logo: contract.logo ?? '',
    use_cases: toStringArray(contract.use_cases),
    verified: toBoolean(contract.verified, false),
    last_verified_date: contract.last_verified_date ?? '',
    playbook_supported: toBoolean(additional.playbook_supported, false),
    max_confidence_level: toNumber(additional.max_confidence_level, 100),
    support_version: contract.support_version ?? '',
    subscription_link: contract.subscription_link ?? '',
    source_code: contract.source_code ?? '',
    manager_supported: toBoolean(contract.manager_supported, false),
    // Legacy compatibility: keep container_* fields for the in-memory/GraphQL
    // contract shape while embedded-manifest-based paths still exist.
    container_version: contract.version ?? '',
    container_image: contract.image_name ?? contract.container_image ?? '',
    container_type: (contract.image_type ?? contract.container_type ?? 'EXTERNAL_IMPORT') as IngestionConnectorType,
    config_schema: sanitizeNewManifestConfigSchema(schema),
  };
};

const toCatalogDefinitionsFromNewManifest = (raw: Record<string, any>): CatalogDefinition[] => {
  if (!raw.id || !Array.isArray(raw.contracts)) {
    throw UnsupportedError('Catalog manifest is missing required fields: id and contracts');
  }

  const catalogId = String(raw.id);
  const contracts = raw.contracts.map((contract: Record<string, any>) => {
    const normalized = normalizeContractFromNewManifest(contract);
    validateManagerSupportedContract({
      catalogId,
      contract: normalized,
      compileValidator: getOrCompileAdapterValidator,
      onMissingConfigSchema: (contractTitle) => {
        logApp.warn('A contract has manager_supported=true but is missing config_schema', { contractTitle });
      },
    });
    return normalized;
  });

  return [{
    id: catalogId,
    name: String(raw.name ?? 'Connector Catalog'),
    description: String(raw.description ?? ''),
    contracts,
  }];
};

const toManifestMetadataFromNewManifest = (raw: Record<string, any>): PersistableManifestMetadata => {
  if (!raw.id || !Array.isArray(raw.contracts)) {
    throw UnsupportedError('Catalog manifest is missing required fields: id and contracts');
  }

  return {
    catalogId: String(raw.id),
    manifestVersion: raw.manifest_version ? String(raw.manifest_version) : undefined,
    productVersion: raw.product_version ? String(raw.product_version) : undefined,
  };
};

export class NewManifestAdapter implements CatalogSourceAdapter {
  async fetch(source: CatalogSourceConfig, options?: { signal?: AbortSignal }): Promise<RawManifest> {
    if (source.kind === 'local') {
      const content = await readFile(source.uri, { encoding: 'utf8', flag: 'r' });
      return JSON.parse(content);
    }

    const res = await fetch(source.uri, { signal: options?.signal });
    if (!res.ok) {
      throw UnsupportedError(`Failed to fetch remote catalog (${res.status}) from ${source.uri}`);
    }
    return res.json();
  }

  toPersistableContracts(raw: RawManifest): CatalogContract[] {
    const manifest = raw as Record<string, any>;
    const normalized = toCatalogDefinitionsFromNewManifest(manifest);
    return normalized[0]?.contracts ?? [];
  }

  toPersistableManifestMetadata(raw: RawManifest): PersistableManifestMetadata {
    const manifest = raw as Record<string, any>;
    return toManifestMetadataFromNewManifest(manifest);
  }
}
