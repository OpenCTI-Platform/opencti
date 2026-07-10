import { JsonSchema } from '@jsonforms/core';
import { IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { filterOutDeprecatedProperties, filterOutDeprecatedRequired } from '@components/data/IngestionCatalog/utils/deprecatedFields';
import { ManagerContractProperty } from './reconcileManagedConnectorContractDataWithSchema';

export interface ContractPropertyGroups {
  requiredProperties: JsonSchema;
  optionalProperties: JsonSchema;
  deprecatedProperties: Record<string, IngestionTypedProperty>;
}

/**
 * Appends a note to password field descriptions so the user knows the current
 * value is masked but can still be overwritten.
 */
export const augmentPasswordDescriptions = (
  properties: ManagerContractProperty[],
): ManagerContractProperty[] => {
  return properties.map(([key, value]) => {
    if (value.format !== 'password') return [key, value];
    return [key, { ...value, description: `${value.description} Current value is hidden, but can still be replaced.` }];
  });
};

/**
 * Splits augmented contract properties into three groups:
 * - `requiredProperties`: non-deprecated required fields (JsonSchema for JsonForms)
 * - `optionalProperties`: non-deprecated optional fields (JsonSchema for JsonForms)
 * - `deprecatedProperties`: deprecated fields (kept separate for conditional display logic)
 */
export const buildContractPropertyGroups = (
  properties: ManagerContractProperty[],
  required: string[],
): ContractPropertyGroups => {
  const propertiesMap = Object.fromEntries(properties);
  const nonDeprecated = filterOutDeprecatedProperties(propertiesMap);

  const requiredArray: ManagerContractProperty[] = [];
  const optionalArray: ManagerContractProperty[] = [];
  const deprecatedArray: ManagerContractProperty[] = [];

  properties.forEach((property) => {
    const [key] = property;
    if (!(key in nonDeprecated)) {
      deprecatedArray.push(property);
      return;
    }
    if (required.includes(key)) {
      requiredArray.push(property);
    } else {
      optionalArray.push(property);
    }
  });

  return {
    requiredProperties: {
      properties: Object.fromEntries(requiredArray),
      // Use the original properties map (not augmented descriptions) to check deprecated flags.
      required: filterOutDeprecatedRequired(required, propertiesMap),
    },
    optionalProperties: {
      properties: Object.fromEntries(optionalArray),
    },
    deprecatedProperties: Object.fromEntries(deprecatedArray),
  };
};
