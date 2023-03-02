import * as R from 'ramda';
import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryRuntimeAttributesArgs } from '../generated/graphql';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { RelationRefDefinition } from '../schema/relationRef-definition';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';

interface MandatoryAttribute {
  name: string
  builtIn: boolean
  mandatory: boolean
  label?: string
}

export const queryMandatoryAttributesDefinition = async (context: AuthContext, entitySetting: BasicStoreEntityEntitySetting) => {
  if (!entitySetting) {
    return [];
  }

  // From schema attributes
  const mandatoryAttributes: MandatoryAttribute[] = [];
  const customizableAttributes: MandatoryAttribute[] = [];

  // From schema attributes
  const attributes = schemaAttributesDefinition.getAttributes(entitySetting.target_type);
  attributes.forEach((attr) => {
    if (attr.mandatoryType === 'external') {
      mandatoryAttributes.push({ name: attr.name, builtIn: true, mandatory: true, label: attr.label });
    }
    if (attr.mandatoryType === 'customizable') {
      customizableAttributes.push({ name: attr.name, builtIn: false, mandatory: false, label: attr.label });
    }
  });

  // From schema relations ref
  const relationsRef: RelationRefDefinition[] = schemaRelationsRefDefinition.getRelationsRef(entitySetting.target_type);
  relationsRef.forEach((rel) => {
    if (rel.mandatoryType === 'external') {
      mandatoryAttributes.push({ name: rel.inputName, builtIn: true, mandatory: true, label: rel.label });
    }
    if (rel.mandatoryType === 'customizable') {
      customizableAttributes.push({ name: rel.inputName, builtIn: false, mandatory: false, label: rel.label });
    }
  });

  const userDefinedAttributes = getAttributesConfiguration(entitySetting);
  userDefinedAttributes?.forEach((userDefinedAttr) => {
    const customizableAttr = customizableAttributes.find((a) => a.name === userDefinedAttr.name);
    if (customizableAttr) {
      customizableAttr.mandatory = userDefinedAttr.mandatory;
    }
  });

  return mandatoryAttributes.concat(customizableAttributes);
};

export const getMandatoryAttributesForSetting = async (context: AuthContext, entitySetting: BasicStoreEntityEntitySetting): Promise<string[]> => {
  const attributes = await queryMandatoryAttributesDefinition(context, entitySetting);
  return attributes.filter((a) => a.mandatory === true).map((a) => a.name);
};

const queryAttributeNames = async (types: string[]) => {
  const attributes = R.uniq(types.map((type) => schemaAttributesDefinition.getAttributeNames(type)).flat());
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: types[0], value: n } }))
  )(attributes);
  return buildPagination(0, null, finalResult, finalResult.length);
};

export const getRuntimeAttributeValues = (context: AuthContext, user: AuthUser, opts: QueryRuntimeAttributesArgs = {} as QueryRuntimeAttributesArgs) => {
  const { attributeName } = opts;
  return elAttributeValues(context, user, attributeName, opts);
};

export const getSchemaAttributeValues = (elementTypes: string[]) => {
  return queryAttributeNames(elementTypes);
};

export const attributeEditField = async (context: AuthContext, {
  id,
  previous,
  current
}: { id: string, previous: string, current: string }) => {
  await elUpdateAttributeValue(context, id, previous, current);
  return id;
};
