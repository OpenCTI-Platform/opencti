import { CUSTOM_FIELDS_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { isEmptyField } from '../../database/utils';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import type { AuthContext, AuthUser } from '../../types/user';
import { getCustomFieldDefinitionsForEntityType } from './custom-field-cache';
import { type BasicStoreEntityCustomFieldDefinition, CUSTOM_FIELD_PREFIX } from './custom-field-types';
import { transformCustomFieldValueAddInput } from './custom-field-validator';

// Custom fields are not part of the static schema: in the inputs built from external data (CSV and JSON mappers,
// forms), each one is described as a standard attribute of its type, so that its value is computed as any other
// attribute, then moved to the custom field values of the input.
const toCustomFieldAttributeDefinition = (definition: BasicStoreEntityCustomFieldDefinition): AttributeDefinition => {
  const base = { name: definition.name, label: definition.label, mandatoryType: 'no', editDefault: false, upsert: false, isFilterable: false } as const;
  switch (definition.field_type) {
    case 'integer':
      return { ...base, type: 'numeric', precision: 'integer', multiple: false };
    case 'boolean':
      return { ...base, type: 'boolean', multiple: false };
    case 'date':
      return { ...base, type: 'date', multiple: false };
    case 'multi_select':
      return { ...base, type: 'string', format: 'short', multiple: true };
    default:
      return { ...base, type: 'string', format: 'short', multiple: false };
  }
};

export const getCustomFieldAttributeDefinitions = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  attributeKeys: string[],
): Promise<Map<string, AttributeDefinition>> => {
  // Only load the definitions when a custom field is used
  if (!isFeatureEnabled(CUSTOM_FIELDS_FEATURE_FLAG) || !attributeKeys.some((key) => key.startsWith(CUSTOM_FIELD_PREFIX))) {
    return new Map();
  }
  const definitions = await getCustomFieldDefinitionsForEntityType(context, user, entityType);
  return new Map(definitions.map((definition) => [definition.name, toCustomFieldAttributeDefinition(definition)]));
};

// Move the custom field values of the input to its custom field values, in the stored format. Empty values are ignored.
export const moveCustomFieldValuesToInput = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  customFieldAttributes: Map<string, AttributeDefinition>,
  entityType: string,
) => {
  const customFieldValueAddInputs = [];
  for (const name of customFieldAttributes.keys()) {
    if (name in input) {
      if (!isEmptyField(input[name])) {
        customFieldValueAddInputs.push({ field_name: name, value: Array.isArray(input[name]) ? input[name] : [input[name]] });
      }
      delete input[name];
    }
  }
  if (customFieldValueAddInputs.length > 0) {
    input.custom_field_values = await transformCustomFieldValueAddInput(context, user, customFieldValueAddInputs, entityType);
  }
};
