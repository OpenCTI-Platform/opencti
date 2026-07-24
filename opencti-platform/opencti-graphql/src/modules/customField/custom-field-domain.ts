import { type EntityOptions, type FilterGroupWithNested, countAllThings, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import {
  type BasicStoreEntityCustomFieldDefinition,
  CUSTOM_FIELD_PREFIX,
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
import { CUSTOM_FIELDS_FEATURE_FLAG } from '../../config/conf';
import { getCustomFieldDefinitionByLabel, getCustomFieldDefinitions, getCustomFieldValueField } from './custom-field-cache';

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
  // Validate the technical name and label are unique among all custom fields (single cache read)
  const existingDefinitions = await getCustomFieldDefinitions(context, user);
  if (existingDefinitions.some((def) => def.name === input.name)) {
    throw ValidationError('A custom field with this technical name already exists', 'nameSuffix', { name: input.name });
  }
  if (existingDefinitions.some((def) => def.label === input.label)) {
    throw ValidationError('A custom field with this label already exists', 'label', { label: input.label });
  }
  // Validate field_type is supported
  const allowedTypes: CustomFieldType[] = ['integer', 'string', 'markdown', 'boolean', 'date', 'select', 'multi_select'];
  if (!allowedTypes.includes(input.field_type as CustomFieldType)) {
    throw FunctionalError('Unsupported custom field type', { field_type: input.field_type, allowed: allowedTypes });
  }
  // Validate integer bounds
  if (input.field_type === 'integer' && input.min_value != null && input.max_value != null && input.min_value > input.max_value) {
    throw FunctionalError('min_value cannot be greater than max_value', { min_value: input.min_value, max_value: input.max_value });
  }
  // Validate select_options is required for select and multi_select types
  if ((input.field_type === 'select' || input.field_type === 'multi_select') && (!input.select_options || input.select_options.length === 0)) {
    throw FunctionalError('select_options must be provided for select type fields');
  }

  // multi_select is intrinsically multi-valued; force the multiple flag so the entity attribute is indexed as an array
  const multiple = input.field_type === 'multi_select' ? true : (input.multiple ?? false);
  const created = await createEntity(context, user, { ...input, multiple }, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates custom field definition \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

/**
 * Cascade deletion: schedules a background task that removes all stored values of a deleted
 * custom field definition from every entity referencing it (async, tracked like any other task).
 */
const scheduleCustomFieldValuesCleanupTask = async (fieldName: string, entityTypes: string[]): Promise<void> => {
  const systemContext = executionContext('custom_field_cascade_delete', SYSTEM_USER);
  // Nested sub-conditions go through `values` (completeSpecialFilterKeys moves them to `nested`);
  // this also avoids depending on the definition cache, already cleared by this point.
  const taskFilters = {
    mode: FilterMode.And,
    filters: [
      ...(entityTypes.length > 0
        ? [{ key: ['entity_type'], values: entityTypes, operator: FilterOperator.Eq, mode: FilterMode.Or }]
        : []),
      { key: ['custom_field_values'], values: [{ key: 'field_name', values: [fieldName], operator: FilterOperator.Eq }] },
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
    const existing = await getCustomFieldDefinitionByLabel(context, user, newLabel);
    if (existing && existing.id !== customFieldDefinitionId) {
      throw ValidationError('A custom field with this label already exists', 'label', { label: newLabel });
    }
  }
  // Prevent removing a select option that is still stored on at least one entity
  const optionsEdit = input.find((i) => i.key === 'select_options');
  if (optionsEdit) {
    const definition = await findById(context, user, customFieldDefinitionId);
    if (definition && (definition.field_type === 'select' || definition.field_type === 'multi_select')) {
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
        // Count entities holding one of the removed options (SYSTEM_USER: check across all entities).
        const valueKey = getCustomFieldValueField(definition.field_type);
        // See scheduleCustomFieldValuesCleanupTask: nested sub-conditions go through `values`, not `nested`.
        const usageFilters: FilterGroupWithNested = {
          mode: FilterMode.And,
          filters: [{
            key: ['custom_field_values'],
            values: [
              { key: 'field_name', values: [definition.name], operator: FilterOperator.Eq },
              { key: valueKey, values: removedOptions, operator: FilterOperator.Eq },
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
      // undefined = bound not part of this edit, null = bound explicitly cleared, number = new bound value
      const readEditedBound = (edit: EditInput | undefined): number | null | undefined => {
        if (!edit) return undefined;
        const raw = Array.isArray(edit.value) ? edit.value[0] : edit.value;
        return raw === null || raw === undefined || raw === '' ? null : Number(raw);
      };
      const editedMin = readEditedBound(minEdit);
      const editedMax = readEditedBound(maxEdit);
      // Bounds coherence (mirrors the creation-time check), computed against the resulting effective bounds
      const effectiveMin = editedMin === undefined ? definition.min_value : editedMin;
      const effectiveMax = editedMax === undefined ? definition.max_value : editedMax;
      if (effectiveMin != null && effectiveMax != null && effectiveMin > effectiveMax) {
        throw FunctionalError('min_value cannot be greater than max_value', { min_value: effectiveMin, max_value: effectiveMax });
      }
      const buildOutOfBoundFilter = (operator: FilterOperator, bound: number): FilterGroupWithNested => ({
        mode: FilterMode.And,
        // The technical name is a recognized special filter key (isCustomFieldFilterKey), adapted
        // by completeSpecialFilterKeys into the proper nested filter on custom_field_values.
        filters: [{ key: [definition.name], values: [String(bound)], operator }],
        filterGroups: [],
      });
      // Only re-scan the bound(s) actually being edited: re-validating an untouched bound against
      // existing data would let unrelated legacy values block edits to the other bound.
      let outOfBoundCount = 0;
      let outOfBoundField: 'min_value' | 'max_value' | undefined;
      if (editedMin != null) {
        const filter = buildOutOfBoundFilter(FilterOperator.Lt, editedMin);
        const count = await countAllThings(context, SYSTEM_USER, { filters: filter });
        if (count > 0) {
          outOfBoundCount += count;
          outOfBoundField = 'min_value';
        }
      }
      if (outOfBoundCount === 0 && editedMax != null) {
        const filter = buildOutOfBoundFilter(FilterOperator.Gt, editedMax);
        const count = await countAllThings(context, SYSTEM_USER, { filters: filter });
        if (count > 0) {
          outOfBoundCount += count;
          outOfBoundField = 'max_value';
        }
      }
      if (outOfBoundCount > 0 && outOfBoundField) {
        throw ValidationError(
          'Cannot restrict the value range: existing entities hold a value outside the new bounds',
          outOfBoundField,
          {
            min_value: effectiveMin,
            max_value: effectiveMax,
            usageCount: outOfBoundCount,
          },
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
  const updated = await customFieldDefinitionEdit(context, user, customFieldDefinitionId, [
    { key: 'entity_types', value: nextTypes, operation: EditOperation.Replace },
    { key: 'entity_type_settings', value: nextSettings, operation: EditOperation.Replace },
  ]);
  // Remove the field's stored values from existing entities of the detached type
  await scheduleCustomFieldValuesCleanupTask(definition.name, [entityType]);
  return updated;
};
