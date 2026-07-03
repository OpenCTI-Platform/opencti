import * as R from 'ramda';
import { elAttributeValues } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { Attribute, QueryRuntimeAttributesArgs } from '../generated/graphql';
import { INTERNAL_ATTRIBUTES } from './attribute-utils';
import { getCustomFieldDefinitionsForEntityType } from '../modules/customField/custom-field-domain';
import type { AttributeDefinition } from '../schema/attribute-definition';

export interface DefaultValue {
  id: string;
  name: string;
}

// -- ATTRIBUTES --

export const getRuntimeAttributeValues = (context: AuthContext, user: AuthUser, opts: QueryRuntimeAttributesArgs = {} as QueryRuntimeAttributesArgs) => {
  const { attributeName } = opts;
  return elAttributeValues(context, user, attributeName, opts);
};

export const getSchemaAttributeNames = (elementTypes: string[]) => {
  const attributes = R.uniq(elementTypes.map((type) => schemaAttributesDefinition.getAttributeNames(type)).flat());
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: elementTypes[0], value: n } })),
  )(attributes);
  // Inject custom field names dynamically for dashboard widgets and distribution queries
  for (const type of elementTypes) {
    const customFieldDefs = getCustomFieldDefinitionsForEntityType(type);
    for (const cfDef of customFieldDefs) {
      if (!finalResult.some((r: any) => r.node.id === cfDef.name)) {
        finalResult.push({ node: { id: cfDef.name, key: type, value: cfDef.name } });
      }
    }
  }
  return buildPagination<Attribute>(0, null, finalResult, finalResult.length);
};

export const getSchemaAttributes = () => {
  const allTypes = schemaAttributesDefinition.getRegisteredTypes();

  return allTypes.map((entityType) => {
    const attributes = schemaAttributesDefinition.getAttributes(entityType);
    const attributesArray = Array.from(attributes.values());

    // Map attributes to TypeAttribute format
    const typeAttributes = attributesArray
      .filter((attr) => !INTERNAL_ATTRIBUTES.includes(attr.name))
      .map((attr) => ({
        name: attr.name,
        type: attr.type,
        label: attr.label || attr.name,
        mandatory: attr.mandatoryType === 'external',
        mandatoryType: attr.mandatoryType,
        editDefault: attr.editDefault,
        multiple: attr.multiple || false,
        upsert: attr.upsert || false,
        // For numeric attributes with scalable property
        scale: attr.type === 'numeric' && (attr as any).scalable ? 'default' : undefined,
        // Default values would need to be fetched from entity settings if needed
        defaultValues: undefined,
      }));

    // Inject custom field attributes dynamically
    const customFieldDefs = getCustomFieldDefinitionsForEntityType(entityType);
    for (const cfDef of customFieldDefs) {
      let attributeType: AttributeDefinition['type'] = 'string';
      if (cfDef.field_type === 'integer') attributeType = 'numeric';
      else if (cfDef.field_type === 'boolean') attributeType = 'boolean';
      else if (cfDef.field_type === 'date') attributeType = 'date';
      typeAttributes.push({
        name: cfDef.name,
        type: attributeType,
        label: cfDef.label,
        mandatory: cfDef.mandatory,
        mandatoryType: cfDef.mandatory ? 'external' : 'no',
        editDefault: true,
        multiple: cfDef.multiple ?? false,
        upsert: true,
        scale: undefined,
        defaultValues: undefined,
      });
    }

    return {
      type: entityType,
      attributes: typeAttributes,
    };
  });
};
