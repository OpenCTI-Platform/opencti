import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from './custom-field-types';
import { FunctionalError } from '../../config/errors';
import { getCustomFieldDefinitionsForEntityType } from './custom-field-cache';
import type { AuthContext, AuthUser } from '../../types/user';

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
