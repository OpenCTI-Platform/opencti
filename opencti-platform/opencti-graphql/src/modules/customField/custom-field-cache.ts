import { getEntitiesListFromCache } from '../../database/cache';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityCustomFieldDefinition, type CustomFieldEntityTypeSetting, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, type CustomFieldType } from './custom-field-types';

// ----- Custom field definitions read through the platform generic cache -----
// Registered like any other cached entity type in cacheManager.ts (writeCacheForEntity),
// so it's kept in sync across every platform instance for free via the existing
// ADDED/EDIT/DELETE pub/sub topics, without any bespoke cache module.

export const getCustomFieldDefinitions = (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityCustomFieldDefinition[]> => {
  return getEntitiesListFromCache<BasicStoreEntityCustomFieldDefinition>(context, user, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
};

/**
 * Get cached custom field definitions for a given entity type.
 */
export const getCustomFieldDefinitionsForEntityType = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<BasicStoreEntityCustomFieldDefinition[]> => {
  const definitions = await getCustomFieldDefinitions(context, user);
  return definitions.filter((def) => def.entity_types && def.entity_types.includes(entityType));
};

/**
 * Resolve the per-entity-type settings (mandatory / default_value) of a definition
 * for a given entity type. Returns undefined if the field is not attached to it.
 * Pure function on already-loaded data: no cache access needed.
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
export const getCustomFieldDefinitionByName = async (
  context: AuthContext,
  user: AuthUser,
  name: string,
): Promise<BasicStoreEntityCustomFieldDefinition | undefined> => {
  const definitions = await getCustomFieldDefinitions(context, user);
  return definitions.find((def) => def.name === name);
};

export const getCustomFieldDefinitionByLabel = async (
  context: AuthContext,
  user: AuthUser,
  label: string,
): Promise<BasicStoreEntityCustomFieldDefinition | undefined> => {
  const definitions = await getCustomFieldDefinitions(context, user);
  return definitions.find((def) => def.label === label);
};

/**
 * Get the value field name in the nested object based on the field type.
 * Pure mapping function: no cache access needed.
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
