import * as R from 'ramda';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from './custom-field-types';
import { FunctionalError } from '../../config/errors';
import { getCustomFieldDefinitionsForEntityType, getCustomFieldSettingForEntityType } from './custom-field-cache';
import type { AuthContext, AuthUser } from '../../types/user';
import { type CustomFieldValueAddInput, type EditInput, EditOperation } from '../../generated/graphql';
import { logApp } from '../../config/conf';

const verifyAddInputValueType = (
  customFieldValueAddInputValue: any[],
  customFieldDefinition: BasicStoreEntityCustomFieldDefinition,
): boolean => {
  // Verify that the value type matches the definition
  // If not, drop
  switch (customFieldDefinition.field_type) {
    case 'integer':
      if (customFieldValueAddInputValue.length != 1 || typeof customFieldValueAddInputValue[0] !== 'number') {
        logApp.warn('Invalid value type for integer custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    case 'string':
    case 'markdown':
      if (customFieldValueAddInputValue.length != 1 || typeof customFieldValueAddInputValue[0] !== 'string') {
        logApp.warn('Invalid value type for string/markdown custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    case 'boolean':
      if (customFieldValueAddInputValue.length != 1 || typeof customFieldValueAddInputValue[0] !== 'boolean') {
        logApp.warn('Invalid value type for boolean custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    case 'date':
      if (customFieldValueAddInputValue.length != 1 || typeof customFieldValueAddInputValue[0] !== 'string') {
        logApp.warn('Invalid value type for date custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    case 'select':
      if (customFieldValueAddInputValue.length != 1 || typeof customFieldValueAddInputValue[0] !== 'string') {
        logApp.warn('Invalid value type for select custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    case 'multi_select':
      if (!customFieldValueAddInputValue.every((v) => typeof v === 'string')) {
        logApp.warn('Invalid value type for multi_select custom field', { field_name: customFieldDefinition.label });
        return false;
      }
      break;
    default:
      throw FunctionalError('Unknown custom field type', { field_type: customFieldDefinition.field_type, field_name: customFieldDefinition.label });
  }
  return true;
};

const extractCustomFieldValueFromAddInputValue = (
  customFieldValueAddInputValue: any[],
  customFieldDefinition: BasicStoreEntityCustomFieldDefinition,
) => {
  // Check if input value is properly typed, ignore input if not
  const isCustomFieldValueProperlyTyped = verifyAddInputValueType(customFieldValueAddInputValue, customFieldDefinition);
  if (!isCustomFieldValueProperlyTyped) {
    return undefined;
  }
  // Transform the input into a CustomFieldValue object
  const customFieldValue: CustomFieldValue = {
    field_id: customFieldDefinition.id,
    field_name: customFieldDefinition.name,
  };
  switch (customFieldDefinition.field_type) {
    case 'integer':
      customFieldValue.int_value = customFieldValueAddInputValue[0] as number;
      break;
    case 'string':
    case 'markdown':
      customFieldValue.string_value = customFieldValueAddInputValue[0] as string;
      break;
    case 'boolean':
      customFieldValue.boolean_value = customFieldValueAddInputValue[0] as boolean;
      break;
    case 'date':
      customFieldValue.date_value = customFieldValueAddInputValue[0] as string;
      break;
    case 'select':
      customFieldValue.select_value = customFieldValueAddInputValue[0] as string;
      break;
    case 'multi_select':
      customFieldValue.select_values = customFieldValueAddInputValue as string[];
      break;
  }
  return customFieldValue;
};

// Transform a customFieldValueAddInput coming from the API into a backend formatted CustomValue, ready to be indexed
export const transformCustomFieldValueAddInput = async (
  context: AuthContext,
  user: AuthUser,
  customFieldValueAddInput: CustomFieldValueAddInput[],
  entityType: string,
): Promise<CustomFieldValue[]> => {
  const customFieldDefinitionsForEntity = await getCustomFieldDefinitionsForEntityType(context, user, entityType);
  const resultCustomFieldValues: CustomFieldValue[] = [];
  for (let i = 0; i < customFieldValueAddInput.length; i++) {
    const currentCustomField = customFieldValueAddInput[i];
    const customFieldDefinition = customFieldDefinitionsForEntity
      .find((d) => d.name === currentCustomField.field_name
        || d.aliases?.some((a) => a === currentCustomField.field_name));
    // Drop custom field add input not in configured custom fields of the entity type
    if (customFieldDefinition) {
      const customFieldValue = extractCustomFieldValueFromAddInputValue(currentCustomField.value, customFieldDefinition);
      if (customFieldValue) {
        resultCustomFieldValues.push(customFieldValue);
      }
    }
  }
  return resultCustomFieldValues;
};

export const getCustomFieldDefaultValueFromEntitySettings = (
  customFieldDefinition: BasicStoreEntityCustomFieldDefinition,
  entityType: string,
) => {
  const customFieldEntitySettings = getCustomFieldSettingForEntityType(customFieldDefinition, entityType);
  if (customFieldEntitySettings
    && customFieldEntitySettings?.default_value
  ) {
    const defaultValue = customFieldEntitySettings?.default_value;
    const customFieldDefaultValue = { field_id: customFieldDefinition.id, field_name: customFieldDefinition.name };
    switch (customFieldDefinition.field_type) {
      case 'integer':
        return { ...customFieldDefaultValue, int_value: Number.parseInt(defaultValue) };
      case 'markdown':
      case 'string':
        return { ...customFieldDefaultValue, string_value: defaultValue };
      case 'select':
        return { ...customFieldDefaultValue, select_value: defaultValue };
      case 'date':
        return { ...customFieldDefaultValue, date_value: defaultValue };
      case 'multi_select':
        return { ...customFieldDefaultValue, select_values: [defaultValue] };
      case 'boolean':
        return { ...customFieldDefaultValue, boolean_value: defaultValue.toLowerCase() === 'true' };
      default:
        throw FunctionalError('Unknown custom field type', { field_type: customFieldDefinition.field_type });
    }
  }

  return undefined;
};

export const fillCustomFieldsDefaultValues = async (
  context: AuthContext,
  user: AuthUser,
  recordInput: Record<string, any>,
  entityType: string,
) => {
  const customFieldDefinitionsForEntity = await getCustomFieldDefinitionsForEntityType(context, user, entityType);
  const currentCustomFields = recordInput.custom_field_values ?? [];
  for (let i = 0; i < customFieldDefinitionsForEntity.length; i++) {
    const customFieldDefinition = customFieldDefinitionsForEntity[i];
    const customFieldEntitySettings = getCustomFieldSettingForEntityType(customFieldDefinition, entityType);
    if (customFieldEntitySettings
      && !currentCustomFields.some((cfv: any) => cfv.field_id === customFieldDefinition.id)
    ) {
      const defaultValue = getCustomFieldDefaultValueFromEntitySettings(customFieldDefinition, entityType);
      if (defaultValue) {
        currentCustomFields.push(defaultValue);
      }
    }
  }
  // If no default value was added and we didn't have any custom field values before, keep it undefined
  if (currentCustomFields.length > 0 || recordInput.custom_field_values) {
    return currentCustomFields;
  } else {
    return undefined;
  }
};
/**
 * Validates an array of custom field values against the definitions for a given entity type.
 * Throws FunctionalError if any validation fails.
 */
export const validateCustomFieldValues = async (
  context: AuthContext,
  user: AuthUser,
  customFieldValues: CustomFieldValue[],
  entityType: string,
): Promise<void> => {
  const values = customFieldValues ?? [];
  const definitions = await getCustomFieldDefinitionsForEntityType(context, user, entityType);
  // No custom fields configured for this entity type
  if (definitions.length === 0) {
    if (values.length > 0) {
      throw FunctionalError('No custom field definitions found for entity type', { entityType });
    }
    return;
  }

  if (values.length > 0) {
    // Check for duplicate field_name entries
    const fieldNames = values.map((v) => v.field_name);
    const uniqueFieldNames = new Set(fieldNames);
    if (fieldNames.length !== uniqueFieldNames.size) {
      throw FunctionalError('Duplicate custom field entries found in customFieldValues', { duplicates: fieldNames.filter((n, i) => fieldNames.indexOf(n) !== i) });
    }

    // Validate each value against its definition
    for (const value of values) {
      const definition = definitions.find((d) => d.name === value.field_name);
      if (!definition) {
        throw FunctionalError('Custom field definition not found for this entity type', { field_name: value.field_name, entityType });
      }
      validateSingleCustomFieldValue(value, definition);
    }
  }

  // Check mandatory fields are present.
  // Runs even when no values are provided, so an omitted mandatory field is rejected.
  const mandatoryDefs = definitions.filter((d) => d.entity_type_settings?.find((s) => s.entity_type === entityType)?.mandatory);
  for (const def of mandatoryDefs) {
    const valueEntry = values.find((v) => v.field_name === def.name);
    if (!valueEntry) {
      throw FunctionalError('Mandatory custom field is missing', { field_name: def.name, label: def.label });
    }
  }
};

// When validating a replace, check consistency of the new values coming in
// When validating a remove, check that removed value wasn't mandatory
// When validating an add, check consistency of the add and verify that current entity doesn't already contain added field
export const validateCustomFieldValuesEditInput = async (
  context: AuthContext,
  user: AuthUser,
  customFieldValuesEditInput: EditInput,
  currentEntity: Record<string, any>,
): Promise<void> => {
  const customFieldsDefinitionForEntityType = await getCustomFieldDefinitionsForEntityType(context, user, currentEntity.entity_type);
  const inputValues = customFieldValuesEditInput.value ?? [];
  if (!customFieldValuesEditInput.operation || customFieldValuesEditInput.operation === EditOperation.Replace) {
    await validateCustomFieldValues(context, user, inputValues, currentEntity.entity_type);
  } else if (customFieldValuesEditInput.operation === EditOperation.Remove) {
    for (let i = 0; i < inputValues.length; i++) {
      const inputValue = inputValues[i];
      if (inputValue.field_id && currentEntity.custom_field_values && currentEntity.custom_field_values.some((cf: any) => cf.field_id === inputValue.field_id)) {
        const customFieldDefinition = customFieldsDefinitionForEntityType.find((cfd) => cfd.id === inputValue.field_id);
        const customFieldEntityTypeDefinition = getCustomFieldSettingForEntityType(customFieldDefinition, currentEntity.entity_type);
        if (customFieldEntityTypeDefinition && customFieldEntityTypeDefinition.mandatory) {
          throw FunctionalError('Cannot remove mandatory custom field value', { field: customFieldDefinition?.name });
        }
      }
    }
  } else if (customFieldValuesEditInput.operation === EditOperation.Add) {
    const currentValues: CustomFieldValue[] = currentEntity.custom_field_values ?? [];
    const incomingFieldIds = inputValues.filter((v: CustomFieldValue) => v.field_id !== undefined).map((v: CustomFieldValue) => v.field_id);
    const preservedValues = currentValues.filter((v) => !incomingFieldIds.includes(v.field_id));
    const mergedInputValues = inputValues.map((incoming: CustomFieldValue) => {
      const existing = currentValues.find((v) => v.field_id === incoming.field_id);
      if (existing && Array.isArray(existing.select_values) && Array.isArray(incoming.select_values)) {
        return { ...incoming, select_values: R.uniq([...existing.select_values, ...incoming.select_values]) };
      }
      return incoming;
    });
    const fullCustomFieldValues = [...preservedValues, ...mergedInputValues];
    await validateCustomFieldValues(context, user, fullCustomFieldValues, currentEntity.entity_type);
  }
};

/**
 * Validates a single custom field value against its definition.
 */
const validateSingleCustomFieldValue = (
  value: CustomFieldValue,
  definition: BasicStoreEntityCustomFieldDefinition,
): void => {
  const { field_type } = definition;

  switch (field_type) {
    case 'integer':
      validateIntegerField(value, definition);
      break;
    case 'string':
    case 'markdown':
      validateStringField(value, definition);
      break;
    case 'boolean':
      validateBooleanField(value);
      break;
    case 'date':
      validateDateField(value);
      break;
    case 'select':
      validateSelectField(value, definition);
      break;
    case 'multi_select':
      validateMultiSelectField(value, definition);
      break;
    default:
      throw FunctionalError('Unknown custom field type', { field_type, field_name: value.field_name });
  }
};

const validateIntegerField = (value: CustomFieldValue, definition: BasicStoreEntityCustomFieldDefinition): void => {
  if (value.int_value === undefined || value.int_value === null) {
    throw FunctionalError('int_value is required for integer type custom field', { field_name: value.field_name });
  }
  if (!Number.isInteger(value.int_value)) {
    throw FunctionalError('int_value must be an integer', { field_name: value.field_name, value: value.int_value });
  }
  if (definition.min_value != null && value.int_value < definition.min_value) {
    throw FunctionalError('int_value is below minimum', { field_name: value.field_name, value: value.int_value, min: definition.min_value });
  }
  if (definition.max_value != null && value.int_value > definition.max_value) {
    throw FunctionalError('int_value is above maximum', { field_name: value.field_name, value: value.int_value, max: definition.max_value });
  }
};

const validateStringField = (value: CustomFieldValue, _definition: BasicStoreEntityCustomFieldDefinition): void => {
  if (value.string_value === undefined || value.string_value === null) {
    throw FunctionalError('string_value is required for string type custom field', { field_name: value.field_name });
  }
  if (typeof value.string_value !== 'string') {
    throw FunctionalError('string_value must be a string', { field_name: value.field_name });
  }
  // Check multiple cardinality: string_value is single for now
  // Multi-value strings can be comma-separated or use a different mechanism in the future
};

const validateBooleanField = (value: CustomFieldValue): void => {
  if (value.boolean_value === undefined || value.boolean_value === null) {
    throw FunctionalError('boolean_value is required for boolean type custom field', { field_name: value.field_name });
  }
  if (typeof value.boolean_value !== 'boolean') {
    throw FunctionalError('boolean_value must be a boolean', { field_name: value.field_name });
  }
};

const validateDateField = (value: CustomFieldValue): void => {
  if (value.date_value === undefined || value.date_value === null) {
    throw FunctionalError('date_value is required for date type custom field', { field_name: value.field_name });
  }
  // Validate ISO date format
  const date = new Date(value.date_value);
  if (Number.isNaN(date.getTime())) {
    throw FunctionalError('date_value must be a valid ISO date string', { field_name: value.field_name, value: value.date_value });
  }
};

const validateSelectField = (value: CustomFieldValue, definition: BasicStoreEntityCustomFieldDefinition): void => {
  if (value.select_value === undefined || value.select_value === null) {
    throw FunctionalError('select_value is required for select type custom field', { field_name: value.field_name });
  }
  if (!definition.select_options || definition.select_options.length === 0) {
    throw FunctionalError('No select_options configured for this custom field', { field_name: value.field_name });
  }
  if (!definition.select_options.includes(value.select_value)) {
    throw FunctionalError('select_value is not in the allowed options', {
      field_name: value.field_name,
      value: value.select_value,
      allowed: definition.select_options,
    });
  }
};

const validateMultiSelectField = (value: CustomFieldValue, definition: BasicStoreEntityCustomFieldDefinition): void => {
  if (value.select_values === undefined || value.select_values === null) {
    throw FunctionalError('select_values is required for multi_select type custom field', { field_name: value.field_name });
  }
  if (!Array.isArray(value.select_values)) {
    throw FunctionalError('select_values must be an array', { field_name: value.field_name });
  }
  if (!definition.select_options || definition.select_options.length === 0) {
    throw FunctionalError('No select_options configured for this custom field', { field_name: value.field_name });
  }
  const invalidValues = value.select_values.filter((v) => !definition.select_options?.includes(v));
  if (invalidValues.length > 0) {
    throw FunctionalError('select_values contains values that are not in the allowed options', {
      field_name: value.field_name,
      value: invalidValues,
      allowed: definition.select_options,
    });
  }
};
