import * as R from 'ramda';
import { elAttributeValues } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { Attribute, QueryRuntimeAttributesArgs, TypeAttribute } from '../generated/graphql';
import { INTERNAL_ATTRIBUTES } from './attribute-utils';
import { getCustomFieldDefinitionsForEntityType, getDynamicTypeAttributeForEntityType } from '../modules/customField/custom-field-cache';

export interface DefaultValue {
  id: string;
  name: string;
}

// -- ATTRIBUTES --

export const getRuntimeAttributeValues = (context: AuthContext, user: AuthUser, opts: QueryRuntimeAttributesArgs = {} as QueryRuntimeAttributesArgs) => {
  const { attributeName } = opts;
  return elAttributeValues(context, user, attributeName, opts);
};

export const getSchemaAttributeNames = async (context: AuthContext, user: AuthUser, elementTypes: string[]) => {
  const attributes = R.uniq(elementTypes.map((type) => schemaAttributesDefinition.getAttributeNames(type)).flat());
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: elementTypes[0], value: n } })),
  )(attributes);
  // Inject custom field names dynamically for dashboard widgets and distribution queries
  for (const type of elementTypes) {
    const customFieldDefs = await getCustomFieldDefinitionsForEntityType(context, user, type);
    for (const cfDef of customFieldDefs) {
      if (!finalResult.some((r: any) => r.node.id === cfDef.name)) {
        finalResult.push({ node: { id: cfDef.name, key: type, value: cfDef.name } });
      }
    }
  }
  return buildPagination<Attribute>(0, null, finalResult, finalResult.length);
};

export const getSchemaAttributes = async (context: AuthContext, user: AuthUser, entityType?: string | null) => {
  const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
  // A single type can be asked, so an API client does not load the whole schema each time
  const types = entityType ? registeredTypes.filter((type) => type === entityType) : registeredTypes;

  return Promise.all(types.map(async (type) => {
    const attributes = schemaAttributesDefinition.getAttributes(type);
    const attributesArray = Array.from(attributes.values());

    // Map attributes to TypeAttribute format
    const typeAttributes = attributesArray
      .filter((attr) => !INTERNAL_ATTRIBUTES.includes(attr.name))
      .map((attr) => ({
        name: attr.name,
        type: attr.type,
        label: attr.label || attr.name,
        description: attr.description ?? null,
        mandatory: attr.mandatoryType === 'external',
        mandatoryType: attr.mandatoryType,
        editDefault: attr.editDefault,
        multiple: attr.multiple || false,
        upsert: attr.upsert || false,
        // For numeric attributes with scalable property
        scale: attr.type === 'numeric' && (attr as any).scalable ? 'default' : undefined,
        // Default values would need to be fetched from entity settings if needed
        defaultValues: undefined,
      } as TypeAttribute));

    // Inject custom field attributes dynamically
    const customFieldAttributes = await getDynamicTypeAttributeForEntityType(context, user, type);
    for (const cfAttribute of customFieldAttributes) {
      typeAttributes.push(cfAttribute);
    }

    return {
      type,
      attributes: typeAttributes,
    };
  }));
};
