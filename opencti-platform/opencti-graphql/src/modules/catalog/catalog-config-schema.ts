import type { CatalogContract } from './catalog-types';

const EXCLUDED_MANAGER_CONFIG_KEYS = new Set([
  'OPENCTI_TOKEN',
  'OPENCTI_URL',
  'OPENCTI_URI',
  'CONNECTOR_TYPE',
  'CONNECTOR_RUN_AND_TERMINATE',
]);

const isObjectRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

export const shouldExcludeManagerConfigKey = (key: string): boolean => {
  return EXCLUDED_MANAGER_CONFIG_KEYS.has(key.toUpperCase());
};

export const sanitizeManagerConfigSchema = (schema: unknown): CatalogContract['config_schema'] => {
  const rawSchema = isObjectRecord(schema) ? schema : {};
  const rawProperties = isObjectRecord(rawSchema.properties) ? rawSchema.properties : {};
  const properties = { ...rawProperties } as CatalogContract['config_schema']['properties'];
  const requiredSource = Array.isArray(rawSchema.required) ? rawSchema.required : [];

  Object.keys(properties).forEach((key) => {
    if (shouldExcludeManagerConfigKey(key)) {
      delete properties[key];
    }
  });

  const required = requiredSource.filter((key): key is string => {
    return typeof key === 'string' && !shouldExcludeManagerConfigKey(key);
  });

  return {
    ...(rawSchema as CatalogContract['config_schema']),
    properties,
    required,
  };
};
