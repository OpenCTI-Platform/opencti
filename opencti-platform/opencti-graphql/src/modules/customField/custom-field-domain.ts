import { type EntityOptions, type FilterGroupWithNested, countAllThings, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import {
  type BasicStoreEntityCustomFieldDefinition,
  CUSTOM_FIELD_PREFIX,
  type CustomFieldEntityTypeSetting,
  type CustomFieldType,
  ENTITY_TYPE_CUSTOM_FIELD_DEFINITION,
  type StoreEntityCustomFieldDefinition,
} from './custom-field-types';
import type { CustomFieldDefinitionAddInput, EditInput } from '../../generated/graphql';
import { BackgroundTaskScope, EditOperation, FilterMode, FilterOperator } from '../../generated/graphql';
import type { DomainFindById } from '../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { createQueryTask } from '../../domain/backgroundTask';
import { ACTION_TYPE_REMOVE_CUSTOM_FIELD_VALUES } from '../../domain/backgroundTask-common';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { publishUserAction } from '../../listener/UserActionListener';
import { FunctionalError, ValidationError } from '../../config/errors';
import { enforceEnableFeatureFlag, executionContext, SYSTEM_USER } from '../../utils/access';
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

/**
 * Get a cached custom field definition by its label.
 */
export const getCustomFieldDefinitionByLabel = (label: string): BasicStoreEntityCustomFieldDefinition | undefined => {
  return customFieldDefinitionsCache.find((def) => def.label === label);
};

/**
 * Technical name must be the custom field prefix followed by lowercase letters,
 * numbers and underscores, starting with a letter (mirrors the frontend Yup rule,
 * enforced here again so the constraint cannot be bypassed via a direct GraphQL call).
 */
const CUSTOM_FIELD_NAME_REGEX = /^x_opencti_cf_[a-z][a-z0-9_]*$/;

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
  name: string,
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
  // Validate name starts with the required prefix and matches the allowed format
  if (!CUSTOM_FIELD_NAME_REGEX.test(input.name)) {
    throw ValidationError(
      'Technical name must start with "x_opencti_cf_" and contain only lowercase letters, numbers and underscores, starting with a letter',
      'nameSuffix',
      { name: input.name },
    );
  }
  // Validate the technical name is unique
  if (getCustomFieldDefinitionByName(input.name)) {
    throw ValidationError('A custom field with this technical name already exists', 'nameSuffix', { name: input.name });
  }
  // Validate the label is unique among all custom fields
  if (getCustomFieldDefinitionByLabel(input.label)) {
    throw ValidationError('A custom field with this label already exists', 'label', { label: input.label });
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

/**
 * Cascade deletion: schedule a background task that removes all stored values of a
 * deleted custom field definition from every entity referencing it. The task is
 * processed asynchronously by the task manager (so it does not block the delete
 * mutation) and is tracked, retried and monitorable like any other background task.
 * Only entities actually holding a value for the field are targeted (nested filter).
 */
const scheduleCustomFieldValuesCleanupTask = async (fieldName: string, entityTypes: string[]): Promise<void> => {
  const systemContext = executionContext('custom_field_cascade_delete', SYSTEM_USER);
  const taskFilters = {
    mode: FilterMode.And,
    filters: [
      ...(entityTypes.length > 0
        ? [{ key: ['entity_type'], values: entityTypes, operator: FilterOperator.Eq, mode: FilterMode.Or }]
        : []),
      { key: ['custom_field_values'], values: [], nested: [{ key: 'field_name', values: [fieldName], operator: FilterOperator.Eq }] },
    ],
    filterGroups: [],
  };
  const input = {
    actions: [{ type: ACTION_TYPE_REMOVE_CUSTOM_FIELD_VALUES, context: { values: [fieldName] } }],
    filters: JSON.stringify(taskFilters),
    scope: BackgroundTaskScope.Knowledge,
    excluded_ids: [],
    search: null,
    orderMode: 'asc',
    description: `Cascade delete of custom field '${fieldName}' values`,
  };
  await createQueryTask(systemContext, SYSTEM_USER, input);
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
  // Reload the cache first so the removed definition is no longer applied during cleanup
  await loadCustomFieldDefinitions(context);
  // Cascade deletion: schedule a background task to clean stored values of this definition from all entities using it
  await scheduleCustomFieldValuesCleanupTask(element.name, element.entity_types ?? []);
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
  // Validate the label stays unique among all custom fields
  const labelEdit = input.find((i) => i.key === 'label');
  if (labelEdit) {
    const newLabel = Array.isArray(labelEdit.value) ? labelEdit.value[0] : labelEdit.value;
    const existing = getCustomFieldDefinitionByLabel(newLabel);
    if (existing && existing.id !== customFieldDefinitionId) {
      throw ValidationError('A custom field with this label already exists', 'label', { label: newLabel });
    }
  }
  // Prevent removing a select option that is still stored on at least one entity
  const optionsEdit = input.find((i) => i.key === 'select_options');
  if (optionsEdit) {
    const definition = await findById(context, user, customFieldDefinitionId);
    if (definition && definition.field_type === 'select') {
      const previousOptions = definition.select_options ?? [];
      const editValues = (Array.isArray(optionsEdit.value) ? optionsEdit.value : [optionsEdit.value]) as string[];
      const editOperation = optionsEdit.operation ?? EditOperation.Replace;
      let removedOptions: string[] = [];
      if (editOperation === EditOperation.Remove) {
        // The provided values are the options being removed
        removedOptions = editValues.filter((option) => previousOptions.includes(option));
      } else if (editOperation === EditOperation.Replace) {
        // The provided values are the new full list; anything missing is removed
        removedOptions = previousOptions.filter((option) => !editValues.includes(option));
      } // EditOperation.Add only adds options, nothing is removed
      if (removedOptions.length > 0) {
        // Count entities holding a value for this field set to one of the removed options.
        // Runs as SYSTEM_USER to cover all entities regardless of the requester's visibility.
        const usageFilters: FilterGroupWithNested = {
          mode: FilterMode.And,
          filters: [{
            key: ['custom_field_values'],
            values: [],
            nested: [
              { key: 'field_name', values: [definition.name], operator: FilterOperator.Eq },
              { key: 'select_value', values: removedOptions, operator: FilterOperator.Eq },
            ],
          }],
          filterGroups: [],
        };
        const usageCount = await countAllThings(context, SYSTEM_USER, { filters: usageFilters });
        if (usageCount > 0) {
          throw ValidationError(
            'Cannot remove a select option that is still used by existing entities',
            'select_options',
            { options: removedOptions, usageCount },
          );
        }
      }
    }
  }
  // Prevent tightening integer bounds beyond a value already stored on an entity
  const minEdit = input.find((i) => i.key === 'min_value');
  const maxEdit = input.find((i) => i.key === 'max_value');
  if (minEdit || maxEdit) {
    const definition = await findById(context, user, customFieldDefinitionId);
    if (definition && definition.field_type === 'integer') {
      const readBound = (edit: EditInput | undefined, fallback: number | undefined): number | undefined => {
        if (!edit) return fallback;
        const raw = Array.isArray(edit.value) ? edit.value[0] : edit.value;
        return raw === null || raw === undefined || raw === '' ? undefined : Number(raw);
      };
      const newMin = readBound(minEdit, definition.min_value);
      const newMax = readBound(maxEdit, definition.max_value);
      // Bounds coherence (mirrors the creation-time check)
      if (newMin != null && newMax != null && newMin > newMax) {
        throw FunctionalError('min_value cannot be greater than max_value', { min_value: newMin, max_value: newMax });
      }
      const buildOutOfBoundFilter = (operator: FilterOperator, bound: number): FilterGroupWithNested => ({
        mode: FilterMode.And,
        filters: [{
          key: ['custom_field_values'],
          values: [],
          nested: [
            { key: 'field_name', values: [definition.name], operator: FilterOperator.Eq },
            { key: 'int_value', values: [String(bound)], operator },
          ],
        }],
        filterGroups: [],
      });
      // Count as SYSTEM_USER to cover all entities regardless of the requester's visibility.
      let outOfBoundCount = 0;
      if (newMin != null) {
        outOfBoundCount += await countAllThings(context, SYSTEM_USER, { filters: buildOutOfBoundFilter(FilterOperator.Lt, newMin) });
      }
      if (outOfBoundCount === 0 && newMax != null) {
        outOfBoundCount += await countAllThings(context, SYSTEM_USER, { filters: buildOutOfBoundFilter(FilterOperator.Gt, newMax) });
      }
      if (outOfBoundCount > 0) {
        throw ValidationError(
          'Cannot restrict the value range: existing entities hold a value outside the new bounds',
          minEdit ? 'min_value' : 'max_value',
          { min_value: newMin, max_value: newMax },
        );
      }
    }
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

export const customFieldDefinitionAddEntityType = async (
  context: AuthContext,
  user: AuthUser,
  customFieldDefinitionId: string,
  entityType: string,
  mandatory: boolean,
  defaultValue?: string | null,
) => {
  const definition = await findById(context, user, customFieldDefinitionId);
  if (!definition) {
    throw FunctionalError('Custom field definition not found', { id: customFieldDefinitionId });
  }
  const currentTypes = definition.entity_types ?? [];
  const currentSettings = definition.entity_type_settings ?? [];
  const nextTypes = currentTypes.includes(entityType) ? currentTypes : [...currentTypes, entityType];
  const nextSettings = [
    ...currentSettings.filter((setting) => setting.entity_type !== entityType),
    { entity_type: entityType, mandatory, default_value: defaultValue ?? undefined },
  ];
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [
    { key: 'entity_types', value: nextTypes, operation: EditOperation.Replace },
    { key: 'entity_type_settings', value: nextSettings, operation: EditOperation.Replace },
  ]);
};

export const customFieldDefinitionUpdateEntityType = async (
  context: AuthContext,
  user: AuthUser,
  customFieldDefinitionId: string,
  entityType: string,
  mandatory: boolean,
  defaultValue?: string | null,
) => {
  const definition = await findById(context, user, customFieldDefinitionId);
  if (!definition) {
    throw FunctionalError('Custom field definition not found', { id: customFieldDefinitionId });
  }
  const currentTypes = definition.entity_types ?? [];
  if (!currentTypes.includes(entityType)) {
    throw FunctionalError('Custom field definition is not attached to this entity type', { id: customFieldDefinitionId, entityType });
  }
  const currentSettings = definition.entity_type_settings ?? [];
  const nextSettings = [
    ...currentSettings.filter((setting) => setting.entity_type !== entityType),
    { entity_type: entityType, mandatory, default_value: defaultValue ?? undefined },
  ];
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [
    { key: 'entity_type_settings', value: nextSettings, operation: EditOperation.Replace },
  ]);
};

export const customFieldDefinitionRemoveEntityType = async (
  context: AuthContext,
  user: AuthUser,
  customFieldDefinitionId: string,
  entityType: string,
) => {
  const definition = await findById(context, user, customFieldDefinitionId);
  if (!definition) {
    throw FunctionalError('Custom field definition not found', { id: customFieldDefinitionId });
  }
  const nextTypes = (definition.entity_types ?? []).filter((type) => type !== entityType);
  const nextSettings = (definition.entity_type_settings ?? []).filter((setting) => setting.entity_type !== entityType);
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [
    { key: 'entity_types', value: nextTypes, operation: EditOperation.Replace },
    { key: 'entity_type_settings', value: nextSettings, operation: EditOperation.Replace },
  ]);
};
