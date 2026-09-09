import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from './custom-field-types';
import { CUSTOM_FIELD_PREFIX } from './custom-field-types';
import { getCustomFieldDefinitions, getCustomFieldValueField } from './custom-field-cache';
import type { AuthContext, AuthUser } from '../../types/user';
import type { FilterEventContext, TesterFunction } from '../../utils/filtering/boolean-logic-engine';
import type { Filter } from '../../generated/graphql';
import { testBooleanFilter, testDateFilter, testNumericFilter, testStringFilter } from '../../utils/filtering/boolean-logic-engine';

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
    // Extract the actual value based on whichever field is set (select_values is the array channel for multi_select)
    const value = cfv.select_values ?? cfv.int_value ?? cfv.string_value ?? cfv.boolean_value ?? cfv.date_value ?? cfv.select_value;
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
export const unflattenStixToCustomFieldValues = async (
  context: AuthContext,
  user: AuthUser,
  stixExtensions: Record<string, any>,
): Promise<CustomFieldValue[] | undefined> => {
  if (!stixExtensions) return undefined;

  const customFieldValues: CustomFieldValue[] = [];
  // Fetch the definitions once (not once per key) to avoid a redundant cache read per custom field.
  const definitions = await getCustomFieldDefinitions(context, user);

  for (const [key, value] of Object.entries(stixExtensions)) {
    if (!key.startsWith(CUSTOM_FIELD_PREFIX)) continue;

    const definition = definitions.find((def) => def.name === key);
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
      case 'select_values':
        cfValue.select_values = Array.isArray(value) ? value.map((v) => String(v)) : [String(value)];
        break;
      default:
        cfValue.string_value = String(value);
    }

    customFieldValues.push(cfValue);
  }

  return customFieldValues.length > 0 ? customFieldValues : undefined;
};

export const getStixCustomFieldValue = (data: Record<string, any>, customFieldName: string, customFieldAliases: string[] | null | undefined) => {
  let result = undefined;
  let resultFound = false;
  // Check the main custom field name first
  if (Object.hasOwn(data, customFieldName)) {
    result = data[customFieldName];
    resultFound = true;
  } else {
    const dataExtensions = data.extensions;
    if (dataExtensions !== null && dataExtensions !== undefined) {
      const extensionsValues = Object.values(dataExtensions) as Record<string, any>;
      for (let i = 0; i < extensionsValues.length; i++) {
        const extensionValue = extensionsValues[i];
        if (Object.hasOwn(extensionValue, customFieldName)) {
          result = extensionValue[customFieldName];
          resultFound = true;
          break;
        }
      }
    }
  }
  let aliasIndex = 0;
  // Check all possible aliases
  while (!resultFound && customFieldAliases && aliasIndex < customFieldAliases.length) {
    const alias = customFieldAliases[aliasIndex];
    if (Object.hasOwn(data, alias)) {
      result = data[alias];
      resultFound = true;
    } else {
      const dataExtensions = data.extensions;
      if (dataExtensions !== null && dataExtensions !== undefined) {
        const extensionsValues = Object.values(dataExtensions) as Record<string, any>;
        for (let i = 0; i < extensionsValues.length; i++) {
          const extensionValue = extensionsValues[i];
          if (Object.hasOwn(extensionValue, alias)) {
            result = extensionValue[alias];
            resultFound = true;
            break;
          }
        }
      }
    }
    aliasIndex++;
  }

  return result;
};

export const buildCustomFieldStixFilterTester = (customFieldDefinition: BasicStoreEntityCustomFieldDefinition): TesterFunction => {
  return (stix: any, filter: Filter, changeContext?: { filterKey: string; eventContext: FilterEventContext }) => {
    const { name, aliases, field_type } = customFieldDefinition;
    const customFieldStixValue = getStixCustomFieldValue(stix, name, aliases);
    switch (field_type) {
      case 'string':
      case 'select':
      case 'multi_select':
        return testStringFilter(filter, customFieldStixValue, changeContext);
      case 'integer':
        return testNumericFilter(filter, customFieldStixValue, changeContext);
      case 'boolean':
        return testBooleanFilter(filter, customFieldStixValue, changeContext);
      case 'date':
        // TODO date testing is deprecated and needs to be updated to work properly
        return testDateFilter(filter, customFieldStixValue);
      default:
        throw new Error(`Unsupported custom field type: ${customFieldDefinition.field_type}`);
    }
  };
};

export const getCustomFieldsStixFilterTesters = async (context: AuthContext, user: AuthUser): Promise<Record<string, TesterFunction>> => {
  const customFieldsDefinitions = await getCustomFieldDefinitions(context, user);
  const customFieldsTestersMap: Record<string, TesterFunction> = {};
  for (let i = 0; i < customFieldsDefinitions.length; i++) {
    const customFieldDefinition = customFieldsDefinitions[i];
    const customFieldTester = buildCustomFieldStixFilterTester(customFieldDefinition);
    const customFieldName = customFieldDefinition.name;
    // Add the tester for the main name
    customFieldsTestersMap[customFieldName] = customFieldTester;
  }
  return customFieldsTestersMap;
};
