import { type BasicStoreEntityCustomFieldDefinition, type CustomFieldEntityTypeSetting, type CustomFieldType } from './custom-field-types';

// ----- In-memory cache of all custom field definitions (loaded at boot) -----
// Kept in its own module (no dependency on utils/access.ts, database/middleware.ts, or the
// heavier CRUD domain functions) so lightweight, read-only consumers (schema attribute
// injection, filter key injection, STIX/filtering utils) don't pull in the full custom field
// domain module and its import graph, which previously caused a circular import (this cache
// file <-> utils/access.ts <-> ... <-> domain/attribute.ts) at platform boot.
let customFieldDefinitionsCache: BasicStoreEntityCustomFieldDefinition[] = [];

/**
 * Replaces the in-memory cache. Called by `loadCustomFieldDefinitions` in custom-field-domain.ts
 * after fetching the definitions from the database (platform startup and every CRUD mutation).
 */
export const setCustomFieldDefinitionsCache = (definitions: BasicStoreEntityCustomFieldDefinition[]): void => {
  customFieldDefinitionsCache = definitions;
};

export const getCustomFieldDefinitions = (): BasicStoreEntityCustomFieldDefinition[] => {
  return customFieldDefinitionsCache;
};

/**
 * Get cached custom field definitions for a given entity type.
 */
export const getCustomFieldDefinitionsForEntityType = (entityType: string): BasicStoreEntityCustomFieldDefinition[] => {
  return customFieldDefinitionsCache.filter(
    (def) => def.entity_types && def.entity_types.includes(entityType),
  );
};

/**
 * Resolve the per-entity-type settings (mandatory / default_value) of a definition
 * for a given entity type. Returns undefined if the field is not attached to it.
 */
export const getCustomFieldSettingForEntityType = (
  definition: BasicStoreEntityCustomFieldDefinition,
  entityType: string,
): CustomFieldEntityTypeSetting | undefined => {
  return definition.entity_type_settings?.find((setting) => setting.entity_type === entityType);
};

/**
 * Get a cached custom field definition by its name (e.g. x_opencti_cf_score).
 */
export const getCustomFieldDefinitionByName = (name: string): BasicStoreEntityCustomFieldDefinition | undefined => {
  return customFieldDefinitionsCache.find((def) => def.name === name);
};

export const getCustomFieldDefinitionByLabel = (label: string): BasicStoreEntityCustomFieldDefinition | undefined => {
  return customFieldDefinitionsCache.find((def) => def.label === label);
};

/**
 * Get the value field name in the nested object based on the field type.
 */
export const getCustomFieldValueField = (fieldType: CustomFieldType): string => {
  switch (fieldType) {
    case 'integer':
      return 'int_value';
    case 'string':
    case 'markdown':
      return 'string_value';
    case 'boolean':
      return 'boolean_value';
    case 'date':
      return 'date_value';
    case 'select':
      return 'select_value';
    case 'multi_select':
      return 'select_values';
    default:
      return 'string_value';
  }
};
