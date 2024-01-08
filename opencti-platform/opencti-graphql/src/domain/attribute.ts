import * as R from 'ramda';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { elAttributeValues } from '../database/engine';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { buildPagination, isNotEmptyField } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryRuntimeAttributesArgs } from '../generated/graphql';
import { defaultScale, getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { internalFindByIds } from '../database/middleware-loader';
import { extractRepresentative } from '../database/entity-representative';
import { telemetry } from '../config/tracing';
import { INTERNAL_ATTRIBUTES, INTERNAL_REFS } from './attribute-utils';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import type { RefAttribute } from '../schema/attribute-definition';

interface ScaleAttribute {
  name: string
  scale: string
}

export interface DefaultValue {
  id: string
  name: string
}

interface AttributeConfigMeta {
  name: string
  type: string
  mandatory: boolean
  mandatoryType: string
  multiple: boolean
  label?: string
  defaultValues?: DefaultValue[]
  scale?: string
}

// -- ATTRIBUTE CONFIGURATION --

// Returns a filtered list of AttributeConfigMeta objects built from schema attributes definition and
// stored entity settings attributes configuration (only attributes that can be customized in entity settings)
export const queryAttributesDefinition = async (context: AuthContext, user: AuthUser, entitySetting: BasicStoreEntityEntitySetting): Promise<AttributeConfigMeta[]> => {
  const queryAttributesDefinitionFn = async () => {
    if (!entitySetting) {
      return [];
    }
    const attributesConfiguration: AttributeConfigMeta[] = [];
    // From schema attributes
    const attributesDefinition = schemaAttributesDefinition.getAttributes(entitySetting.target_type);
    attributesDefinition.forEach((attr) => {
      if (attr.editDefault || attr.mandatoryType === 'external' || attr.mandatoryType === 'customizable') {
        const attributeConfig: AttributeConfigMeta = {
          name: attr.name,
          label: attr.label,
          type: attr.type,
          mandatoryType: attr.mandatoryType,
          multiple: attr.multiple,
          mandatory: false,
        };
        if (attr.mandatoryType === 'external') {
          attributeConfig.mandatory = true;
        }
        if (attr.type === 'numeric' && attr.scalable) { // return default scale
          attributeConfig.scale = defaultScale;
        }
        attributesConfiguration.push(attributeConfig);
      }
    });

    // From schema relations ref
    const relationsRef: RefAttribute[] = schemaRelationsRefDefinition.getRelationsRef(entitySetting.target_type);
    relationsRef.forEach((rel) => {
      if (rel.mandatoryType === 'external' || rel.mandatoryType === 'customizable') {
        const attributeConfig: AttributeConfigMeta = {
          name: rel.name,
          label: rel.label,
          type: 'string',
          mandatoryType: rel.mandatoryType,
          multiple: rel.multiple,
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
        if (customizableAttr.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
          customizableAttr.mandatory = userDefinedAttr.mandatory;
        }
        if (isNotEmptyField(userDefinedAttr.default_values)) {
          customizableAttr.defaultValues = userDefinedAttr.default_values?.map((v) => ({ id: v } as DefaultValue));
        }
        if (customizableAttr.scale && isNotEmptyField(userDefinedAttr.scale)) {
          // override default scale
          customizableAttr.scale = JSON.stringify(userDefinedAttr.scale);
        }
      }
    });
    // Resolve default values ref
    const resolveRef = (attributes: AttributeConfigMeta[]) => {
      return Promise.all(attributes.map((attr) => {
        if (attr.name !== 'objectMarking' && relationsRef.map((ref) => ref.name).includes(attr.name)) {
          return internalFindByIds(context, user, attr.defaultValues?.map((v) => v.id) ?? [])
            .then((data) => ({
              ...attr,
              defaultValues: data.map((v) => ({
                id: v.internal_id,
                name: extractRepresentative(v).main ?? v.internal_id,
              }))
            }));
        }
        return {
          ...attr,
          defaultValues: attr.defaultValues?.map((v) => ({
            id: v.id,
            name: v.id
          }))
        };
      }));
    };
    return resolveRef(attributesConfiguration);
  };

  return telemetry(context, user, 'ATTRIBUTES', {
    [SemanticAttributes.DB_NAME]: 'attributes_domain',
    [SemanticAttributes.DB_OPERATION]: 'attributes_definition',
  }, queryAttributesDefinitionFn);
};

export const getScaleAttributesForSetting = async (context: AuthContext, user: AuthUser, entitySetting: BasicStoreEntityEntitySetting): Promise<ScaleAttribute[]> => {
  const attributes = await queryAttributesDefinition(context, user, entitySetting);
  return attributes.filter((a) => a.scale).map((a) => ({ name: a.name, scale: a.scale ?? '' }));
};

export const getMandatoryAttributesForSetting = async (context: AuthContext, user: AuthUser, entitySetting: BasicStoreEntityEntitySetting): Promise<string[]> => {
  const attributes = await queryAttributesDefinition(context, user, entitySetting);
  return attributes.filter((a) => a.mandatory).map((a) => a.name);
};

export const getDefaultValuesAttributesForSetting = async (context: AuthContext, user: AuthUser, entitySetting: BasicStoreEntityEntitySetting) => {
  const attributes = await queryAttributesDefinition(context, user, entitySetting);
  return attributes.filter((a) => a.defaultValues).map((a) => ({ ...a, defaultValues: a.defaultValues ?? [] }));
};

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
  return buildPagination(0, null, finalResult, finalResult.length);
};

export const getSchemaAttributes = async (context: AuthContext, entityType: string) => {
  // Handle attributes
  const mapAttributes = schemaAttributesDefinition.getAttributes(entityType);
  const resultAttributes: AttributeConfigMeta[] = Array.from(mapAttributes.values())
    .filter((attribute) => !INTERNAL_ATTRIBUTES.includes(attribute.name))
    .map((attribute) => ({
      ...attribute,
      mandatory: attribute.mandatoryType === 'external',
    }));

  // Handle ref
  const refs = schemaRelationsRefDefinition.getRelationsRef(entityType);
  const resultRefs: AttributeConfigMeta[] = refs
    .filter((ref) => !INTERNAL_REFS.includes(ref.name))
    .map((ref) => ({
      name: ref.name,
      label: ref.label,
      type: 'ref',
      mandatoryType: ref.mandatoryType,
      multiple: ref.multiple,
      mandatory: ref.mandatoryType === 'external',
    }));
  if (isStixCoreRelationship(entityType)) {
    resultRefs.push({
      name: 'from',
      label: 'from',
      type: 'ref',
      mandatoryType: 'external',
      multiple: false,
      mandatory: true,
    });
    resultRefs.push({
      name: 'to',
      label: 'to',
      type: 'ref',
      mandatoryType: 'external',
      multiple: false,
      mandatory: true,
    });
  }

  const results = [...resultAttributes, ...resultRefs];

  // Handle user defined attributes
  const entitySetting = await getEntitySettingFromCache(context, entityType);
  if (entitySetting) {
    const userDefinedAttributes = getAttributesConfiguration(entitySetting);
    userDefinedAttributes?.forEach((userDefinedAttr) => {
      const customizableAttr = results.find((a) => a.name === userDefinedAttr.name);
      if (customizableAttr) {
        if (customizableAttr.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
          customizableAttr.mandatory = userDefinedAttr.mandatory;
        }
      }
    });
  }

  return results;
};
