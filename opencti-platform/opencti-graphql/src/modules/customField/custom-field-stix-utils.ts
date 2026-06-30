import type { CustomFieldValue } from './custom-field-types';
import { CUSTOM_FIELD_PREFIX } from './custom-field-types';
import { getCustomFieldDefinitionByName, getCustomFieldValueField } from './custom-field-domain';

/**
 * Flatten custom_field_values array into a flat object for STIX export.
 * Each custom field becomes a property like x_opencti_cf_score: 5 inside the STIX extension.
 */
export const flattenCustomFieldValuesForStix = (customFieldValues?: CustomFieldValue[]): Record<string, any> => {
  if (!customFieldValues || customFieldValues.length === 0) {
    return {};
  }
  const result: Record<string, any> = {};
  for (const cfv of customFieldValues) {
    // Extract the actual value based on whichever field is set
    const value = cfv.int_value ?? cfv.string_value ?? cfv.boolean_value ?? cfv.date_value ?? cfv.select_value;
    if (value !== undefined && value !== null) {
      result[cfv.field_name] = value;
    }
  }
  return result;
};

/**
 * Convert flat STIX properties (x_opencti_cf_*) back to the nested custom_field_values array
 * for ingestion into OpenCTI.
 * Returns undefined if no custom field properties are found.
 */
export const unflattenStixToCustomFieldValues = (stixExtensions: Record<string, any>): CustomFieldValue[] | undefined => {
  if (!stixExtensions) return undefined;

  const customFieldValues: CustomFieldValue[] = [];

  for (const [key, value] of Object.entries(stixExtensions)) {
    if (!key.startsWith(CUSTOM_FIELD_PREFIX)) continue;

    const definition = getCustomFieldDefinitionByName(key);
    if (!definition) {
      // Skip unknown custom fields — do not auto-create definitions
      continue;
    }

    const valueField = getCustomFieldValueField(definition.field_type);
    const cfValue: CustomFieldValue = {
      field_id: definition.id,
      field_name: key,
    };

    // Set the appropriate value field
    switch (valueField) {
      case 'int_value':
        cfValue.int_value = typeof value === 'number' ? value : Number(value);
        break;
      case 'string_value':
        cfValue.string_value = String(value);
        break;
      case 'boolean_value':
        cfValue.boolean_value = typeof value === 'boolean' ? value : value === 'true';
        break;
      case 'date_value':
        cfValue.date_value = String(value);
        break;
      case 'select_value':
        cfValue.select_value = String(value);
        break;
      default:
        cfValue.string_value = String(value);
    }

    customFieldValues.push(cfValue);
  }

  return customFieldValues.length > 0 ? customFieldValues : undefined;
};
