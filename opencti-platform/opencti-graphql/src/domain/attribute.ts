import * as R from 'ramda';
import { elAttributeValues } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { Attribute, QueryRuntimeAttributesArgs } from '../generated/graphql';
import { INTERNAL_ATTRIBUTES } from './attribute-utils';

export interface DefaultValue {
  id: string
  name: string
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
    R.map((n) => ({ node: { id: n, key: elementTypes[0], value: n } }))
  )(attributes);
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
        defaultValues: undefined
      }));

    return {
      type: entityType,
      attributes: typeAttributes
    };
  });
};
