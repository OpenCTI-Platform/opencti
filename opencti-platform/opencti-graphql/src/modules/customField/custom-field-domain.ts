import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomFieldDefinition, CUSTOM_FIELD_PREFIX, type CustomFieldType, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, type StoreEntityCustomFieldDefinition } from './custom-field-types';
import type { CustomFieldDefinitionAddInput, EditInput } from '../../generated/graphql';
import { EditOperation, FilterMode, FilterOperator } from '../../generated/graphql';
import type { DomainFindById } from '../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { publishUserAction } from '../../listener/UserActionListener';
import { FunctionalError } from '../../config/errors';
import { enforceEnableFeatureFlag, SYSTEM_USER } from '../../utils/access';
import { CUSTOM_FIELDS_FEATURE_FLAG, logApp } from '../../config/conf';

// ----- In-memory cache of all custom field definitions (loaded at boot) -----
let customFieldDefinitionsCache: BasicStoreEntityCustomFieldDefinition[] = [];

/**
 * Load all custom field definitions from the database into memory.
 * Called at platform startup and when definitions are modified.
 */
export const loadCustomFieldDefinitions = async (context: AuthContext): Promise<void> => {
  const definitions = await fullEntitiesList<BasicStoreEntityCustomFieldDefinition>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_CUSTOM_FIELD_DEFINITION],
  );
  customFieldDefinitionsCache = definitions;
  logApp.info(`[CUSTOM_FIELDS] Loaded ${definitions.length} custom field definitions`);
};

/**
 * Get all cached custom field definitions.
 */
export const getCustomFieldDefinitions = (): BasicStoreEntityCustomFieldDefinition[] => {
  return customFieldDefinitionsCache;
};

/**
 * Get cached custom field definitions for a given entity type.
 */
export const getCustomFieldDefinitionsForEntityType = (entityType: string): BasicStoreEntityCustomFieldDefinition[] => {
  return customFieldDefinitionsCache.filter(
    (def) => def.entity_types && def.entity_types.includes(entityType)
  );
};

/**
 * Get a cached custom field definition by its name (e.g. x_opencti_cf_score).
 */
export const getCustomFieldDefinitionByName = (name: string): BasicStoreEntityCustomFieldDefinition | undefined => {
  return customFieldDefinitionsCache.find((def) => def.name === name);
};

/**
 * Check if a filter key corresponds to a custom field.
 */
export const isCustomFieldKey = (key: string): boolean => {
  return key.startsWith(CUSTOM_FIELD_PREFIX);
};

/**
 * Get the value field name in the nested object based on the field type.
 */
export const getCustomFieldValueField = (fieldType: CustomFieldType): string => {
  switch (fieldType) {
    case 'integer':
      return 'int_value';
    case 'string':
      return 'string_value';
    case 'boolean':
      return 'boolean_value';
    case 'date':
      return 'date_value';
    case 'select':
      return 'select_value';
    default:
      return 'string_value';
  }
};

// ----- Domain CRUD operations -----

export const findById: DomainFindById<BasicStoreEntityCustomFieldDefinition> = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string) => {
  return storeLoadById(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
};

export const findCustomFieldDefinitionsPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCustomFieldDefinition>) => {
  return pageEntitiesConnection<BasicStoreEntityCustomFieldDefinition>(context, user, [ENTITY_TYPE_CUSTOM_FIELD_DEFINITION], opts);
};

export const findCustomFieldDefinitionsForEntityType = (context: AuthContext, user: AuthUser, entityType: string) => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['entity_types'], values: [entityType], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  return pageEntitiesConnection<BasicStoreEntityCustomFieldDefinition>(context, user, [ENTITY_TYPE_CUSTOM_FIELD_DEFINITION], { filters });
};

export const findCustomFieldDefinitionByName = async (
  context: AuthContext,
  user: AuthUser,
  name: string
): Promise<BasicStoreEntityCustomFieldDefinition | null> => {
  const result = await findCustomFieldDefinitionsPaginated(context, user, {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['name'], values: [name], operator: FilterOperator.Eq }],
      filterGroups: [],
    },
    first: 1,
  });
  return result.edges.length > 0 ? result.edges[0].node : null;
};

export const customFieldDefinitionAdd = async (context: AuthContext, user: AuthUser, input: CustomFieldDefinitionAddInput) => {
  enforceEnableFeatureFlag(CUSTOM_FIELDS_FEATURE_FLAG);
  // Validate name starts with the required prefix
  if (!input.name.startsWith(CUSTOM_FIELD_PREFIX)) {
    throw FunctionalError('Custom field name must start with the prefix "x_opencti_cf_"', { name: input.name });
  }
  // Validate field_type is supported
  const allowedTypes: CustomFieldType[] = ['integer', 'string', 'boolean', 'date', 'select'];
  if (!allowedTypes.includes(input.field_type as CustomFieldType)) {
    throw FunctionalError('Unsupported custom field type', { field_type: input.field_type, allowed: allowedTypes });
  }
  // Validate integer bounds
  if (input.field_type === 'integer' && input.min_value != null && input.max_value != null && input.min_value > input.max_value) {
    throw FunctionalError('min_value cannot be greater than max_value', { min_value: input.min_value, max_value: input.max_value });
  }
  // Validate select_options is required for select type
  if (input.field_type === 'select' && (!input.select_options || input.select_options.length === 0)) {
    throw FunctionalError('select_options must be provided for select type fields');
  }

  const created = await createEntity(context, user, { ...input, multiple: input.multiple ?? false }, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates custom field definition \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input },
  });
  // Reload the cache after creation
  await loadCustomFieldDefinitions(context);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const customFieldDefinitionDelete = async (context: AuthContext, user: AuthUser, customFieldDefinitionId: string) => {
  enforceEnableFeatureFlag(CUSTOM_FIELDS_FEATURE_FLAG);
  const element = await deleteElementById<StoreEntityCustomFieldDefinition>(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes custom field definition \`${element.name}\``,
    context_data: { id: customFieldDefinitionId, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input: element },
  });
  // TODO: Cascade deletion - clean custom_field_values from all affected entities (background task)
  // Reload the cache after deletion
  await loadCustomFieldDefinitions(context);
  return customFieldDefinitionId;
};

export const customFieldDefinitionEdit = async (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, input: EditInput[]) => {
  enforceEnableFeatureFlag(CUSTOM_FIELDS_FEATURE_FLAG);
  // Prevent changing field_type (immutable after creation)
  const forbiddenKeys = ['field_type', 'name'];
  const attemptedForbidden = input.filter((i) => forbiddenKeys.includes(i.key));
  if (attemptedForbidden.length > 0) {
    throw FunctionalError('Cannot modify immutable fields on a custom field definition', { keys: attemptedForbidden.map((i) => i.key) });
  }

  const { element: updatedElem } = await updateAttribute<StoreEntityCustomFieldDefinition>(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for custom field definition \`${updatedElem.name}\``,
    context_data: { id: customFieldDefinitionId, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input },
  });
  // Reload the cache after edit
  await loadCustomFieldDefinitions(context);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const customFieldDefinitionAddEntityType = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, entityType: string) => {
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [{ key: 'entity_types', value: [entityType], operation: EditOperation.Add }]);
};

export const customFieldDefinitionRemoveEntityType = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, entityType: string) => {
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [{ key: 'entity_types', value: [entityType], operation: EditOperation.Remove }]);
};
