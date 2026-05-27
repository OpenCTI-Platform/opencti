import * as R from 'ramda';
import { elAttributeValues } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { Attribute, QueryRuntimeAttributesArgs } from '../generated/graphql';
import { INTERNAL_ATTRIBUTES } from './attribute-utils';
import type { AttrType, MandatoryType } from '../schema/attribute-definition';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';

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
  return buildPagination<Attribute>(0, null, finalResult, finalResult.length);
};

interface SchemasAttributeType {
  name: string;
  type: AttrType;
  label: string;
  mandatory: boolean;
  mandatoryType: MandatoryType;
  editDefault: boolean;
  multiple: boolean;
  upsert: boolean;
  scale: string | undefined;
  defaultValues: undefined;
}

export const createCustomFieldAttributes = (entityType: string) => {
  // FIXME customField POC hack
  const allAttributes: SchemasAttributeType[] = [];
  if (entityType === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
    allAttributes.push({
      name: 'x_opencti_cf_score',
      type: 'numeric',
      label: 'cf score',
      mandatory: false,
      mandatoryType: 'internal',
      editDefault: true,
      upsert: true,
      multiple: false,
      defaultValues: undefined,
      scale: undefined,
    });

    allAttributes.push({
      name: 'x_opencti_cf_comment',
      type: 'string',
      label: 'cf comment',
      mandatory: false,
      mandatoryType: 'internal',
      editDefault: true,
      upsert: true,
      multiple: false,
      defaultValues: undefined,
      scale: undefined,
    });
  }
  return allAttributes;
};

export const getSchemaAttributes = () => {
  const allTypes = schemaAttributesDefinition.getRegisteredTypes();

  return allTypes.map((entityType) => {
    const attributes = schemaAttributesDefinition.getAttributes(entityType);
    const attributesArray = Array.from(attributes.values());

    // Map attributes to TypeAttribute format
    const typeAttributes = attributesArray
      .filter((attr) => !INTERNAL_ATTRIBUTES.includes(attr.name))
      .map((attr) => (<SchemasAttributeType>{
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

    const customFieldAttributes = createCustomFieldAttributes(entityType);
    typeAttributes.push(...customFieldAttributes);
    return {
      type: entityType,
      attributes: typeAttributes,
    };
  });
};
