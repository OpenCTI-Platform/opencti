import * as R from 'ramda';
import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { schemaDefinition } from '../schema/schema-register';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryRuntimeAttributesArgs } from '../generated/graphql';
import { getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';

const queryAttributeNames = async (types: string[]) => {
  const attributes = R.uniq(types.map((type) => schemaDefinition.getAttributeNames(type)).flat());

  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: types[0], value: n } }))
  )(attributes);
  return buildPagination(0, null, finalResult, finalResult.length);
};

interface MandatoryAttribute {
  name: string
  builtIn: boolean
  mandatory?: boolean
}

export const queryMandatoryAttributes = async (context: AuthContext, subTypeId: string) => {
  const mandatoryAttributes: MandatoryAttribute[] = schemaDefinition.getAttributes(subTypeId)
    .filter((attr) => attr.mandatoryType === 'external')
    .map((attr) => ({ name: attr.name, builtIn: true, mandatory: true }));

  const customizableAttributes: MandatoryAttribute[] = schemaDefinition.getAttributes(subTypeId)
    .filter((attr) => attr.mandatoryType === 'customizable')
    .map((attr) => ({ name: attr.name, builtIn: false, mandatory: false }));

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
