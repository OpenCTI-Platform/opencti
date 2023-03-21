import * as R from 'ramda';
import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryRuntimeAttributesArgs } from '../generated/graphql';
import { defaultScale, getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { RelationRefDefinition } from '../schema/relationRef-definition';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';

interface ScaleAttribute {
  name: string
  scale: string
}

interface AttributeConfigMeta {
  name: string
  mandatoryType: string
  mandatory: boolean
  label?: string
  scale?: string
}

// Returns a filtered list of AttributeConfigMeta objects built from schema attributes definition and
// stored entity settings attributes configuration (only attributes that can be customized in entity settings)
export const queryAttributesDefinition = async (context: AuthContext, entitySetting: BasicStoreEntityEntitySetting): Promise<AttributeConfigMeta[]> => {
  if (!entitySetting) {
    return [];
  }
  const attributesConfiguration: any[] = [];
  // From schema attributes
  const attributesDefinition = schemaAttributesDefinition.getAttributes(entitySetting.target_type);
  attributesDefinition.forEach((attr) => {
    if (attr.mandatoryType === 'external' || attr.mandatoryType === 'customizable' || attr.scalable) {
      const attributeConfig: AttributeConfigMeta = {
        name: attr.name,
        label: attr.label,
        mandatoryType: attr.mandatoryType,
        mandatory: false,
      };
      if (attr.mandatoryType === 'external') {
        attributeConfig.mandatory = true;
      }
      if (attr.scalable) { // return default scale
        attributeConfig.scale = defaultScale;
      }
      attributesConfiguration.push(attributeConfig);
    }
  });

  // From schema relations ref
  const relationsRef: RelationRefDefinition[] = schemaRelationsRefDefinition.getRelationsRef(entitySetting.target_type);
  relationsRef.forEach((rel) => {
    if (rel.mandatoryType === 'external' || rel.mandatoryType === 'customizable') {
      const attributeConfig: AttributeConfigMeta = {
        name: rel.inputName,
        label: rel.label,
        mandatoryType: rel.mandatoryType,
        mandatory: false,
      };
      if (rel.mandatoryType === 'external') {
        attributeConfig.mandatory = true;
      }
      attributesConfiguration.push(attributeConfig);
    }
  });

  // override with stored attributes configuration in entitySettings
  const userDefinedAttributes = getAttributesConfiguration(entitySetting);
  userDefinedAttributes?.forEach((userDefinedAttr) => {
    const customizableAttr = attributesConfiguration.find((a) => a.name === userDefinedAttr.name);
    if (customizableAttr) {
      if (customizableAttr.mandatoryType === 'customizable' && !!userDefinedAttr.mandatory) {
        customizableAttr.mandatory = userDefinedAttr.mandatory;
      }
      if (customizableAttr.scale && userDefinedAttr.scale) {
        // override default scale
        customizableAttr.scale = JSON.stringify(userDefinedAttr.scale);
      }
    }
  });
  return attributesConfiguration;
};

export const getScaleAttributesForSetting = async (context: AuthContext, entitySetting: BasicStoreEntityEntitySetting): Promise<ScaleAttribute[]> => {
  const attributes = await queryAttributesDefinition(context, entitySetting);
  return attributes.filter((a) => a.scale).map((a) => ({ name: a.name, scale: a.scale ?? '' }));
};

export const getMandatoryAttributesForSetting = async (context: AuthContext, entitySetting: BasicStoreEntityEntitySetting): Promise<string[]> => {
  const attributes = await queryAttributesDefinition(context, entitySetting);
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
