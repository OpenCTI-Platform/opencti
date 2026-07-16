import { readFile } from 'node:fs/promises';
import path from 'node:path';
import conf, { PLATFORM_VERSION } from '../../config/conf';
import filigranCatalog from '../../__generated__/opencti-manifest.json';
import type { CatalogContract, CatalogDefinition, IngestionConnectorType } from './catalog-types';
import { buildInternalCatalog, type InternalCatalog } from './catalog-cache';
import { UnsupportedError } from '../../config/errors';

export type CatalogSourceConfig = {
  kind: 'remote' | 'local';
  uri: string;
};

export type CatalogResolutionConfig = {
  source: CatalogSourceConfig;
  originalUri: string;
};

export type RawManifest = unknown;

export interface CatalogSourceAdapter {
  fetch(source: CatalogSourceConfig, options?: { signal?: AbortSignal }): Promise<RawManifest>;
  toInternalCatalog(raw: RawManifest): InternalCatalog;
}

const CATALOG_PRODUCT = 'opencti';
const CATALOG_INTEGRATION_TYPE = 'connectors';

const isHttpUri = (value: string) => value.startsWith('http://') || value.startsWith('https://');

export const resolveCatalogSource = (uri?: string | null): CatalogResolutionConfig => {
  const configuredUri = uri?.trim();

  if (!configuredUri) {
    const xtmHubUrl = conf.get('xtm:xtmhub_url');
    const remoteUri = `${xtmHubUrl}/${CATALOG_PRODUCT}/${PLATFORM_VERSION}/${CATALOG_INTEGRATION_TYPE}/manifests/latest`;
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
    container_version: contract.version ?? '',
    container_image: contract.image_name ?? contract.container_image ?? '',
    container_type: (contract.image_type ?? contract.container_type ?? 'EXTERNAL_IMPORT') as IngestionConnectorType,
    config_schema: {
      ...defaultConfigSchema,
      ...schema,
      properties: schema?.properties ?? {},
      required: schema?.required ?? [],
      additionalProperties: schema?.additionalProperties ?? true,
    },
  };
};

const toCatalogDefinitionsFromNewManifest = (raw: Record<string, any>): CatalogDefinition[] => {
  if (!raw.id || !Array.isArray(raw.contracts)) {
    throw UnsupportedError('Catalog manifest is missing required fields: id and contracts');
  }

  const contracts = raw.contracts.map((contract: Record<string, any>) => normalizeContractFromNewManifest(contract));

  return [{
    id: String(raw.id),
    name: String(raw.name ?? 'Connector Catalog'),
    description: String(raw.description ?? ''),
    contracts,
  }];
};

export class LegacyManifestAdapter implements CatalogSourceAdapter {
  async fetch(_source: CatalogSourceConfig): Promise<RawManifest> {
    const customCatalogs: string[] = conf.get('app:custom_catalogs') ?? [];
    const definitions: CatalogDefinition[] = [filigranCatalog as unknown as CatalogDefinition];

    for (let index = 0; index < customCatalogs.length; index += 1) {
      const customCatalogPath = customCatalogs[index];
      const content = await readFile(customCatalogPath, { encoding: 'utf8', flag: 'r' });
      definitions.push(JSON.parse(content) as CatalogDefinition);
    }

    return definitions;
  }

  toInternalCatalog(raw: RawManifest): InternalCatalog {
    const catalogDefinitions = raw as CatalogDefinition[];
    return buildInternalCatalog(catalogDefinitions);
  }
}

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

  toInternalCatalog(raw: RawManifest): InternalCatalog {
    const normalized = toCatalogDefinitionsFromNewManifest(raw as Record<string, any>);
    return buildInternalCatalog(normalized);
  }
}
