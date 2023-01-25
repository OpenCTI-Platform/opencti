import * as R from 'ramda';
import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryRuntimeAttributesArgs } from '../generated/graphql';
import { getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { getParentTypes } from '../schema/schemaUtils';
import type { RelationRefDefinition } from '../schema/relationRef-definition';

interface MandatoryAttribute {
  name: string
  builtIn: boolean
  mandatory: boolean
  label?: string
}

export const queryMandatoryAttributes = async (context: AuthContext, subTypeId: string) => {
  // From schema attributes
  const mandatoryAttributes: MandatoryAttribute[] = [];
  const customizableAttributes: MandatoryAttribute[] = [];

  schemaAttributesDefinition.getAttributes(subTypeId)
    .forEach((attr) => {
      if (attr.mandatoryType === 'external') {
        mandatoryAttributes.push({ name: attr.name, builtIn: true, mandatory: true, label: attr.label });
      }
      if (attr.mandatoryType === 'customizable') {
        customizableAttributes.push({ name: attr.name, builtIn: false, mandatory: false, label: attr.label });
      }
    });

  // From schema relations ref
  const types = getParentTypes(subTypeId);
  types.push(subTypeId);

  const relationsRef: RelationRefDefinition[] = [];
  types.forEach((type) => {
    relationsRef.push(...schemaRelationsRefDefinition.getRelationsRef(type) ?? []);
  });

  relationsRef.forEach((rel) => {
    if (rel.mandatoryType === 'external') {
      mandatoryAttributes.push({ name: rel.inputName, builtIn: true, mandatory: true, label: rel.label });
    }
    if (rel.mandatoryType === 'customizable') {
      customizableAttributes.push({ name: rel.inputName, builtIn: false, mandatory: false, label: rel.label });
    }
  });

  const entitySetting = await getEntitySettingFromCache(context, subTypeId);
  if (entitySetting) {
    const userDefinedAttributes = getAttributesConfiguration(entitySetting);

    userDefinedAttributes?.forEach((userDefinedAttr) => {
      const customizableAttr = customizableAttributes.find((a) => a.name === userDefinedAttr.name);
      if (customizableAttr) {
        customizableAttr.mandatory = userDefinedAttr.mandatory;
      }
    });
  }

  return mandatoryAttributes.concat(customizableAttributes);
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
