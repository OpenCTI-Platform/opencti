import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityEntitySetting } from './entitySetting-types';
import { defaultScale, type EntitySettingSchemaAttribute, getAttributesConfiguration } from './entitySetting-utils';
import { telemetry } from '../../config/tracing';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { AttributeDefinition, RefAttribute } from '../../schema/attribute-definition';
import { isNotEmptyField } from '../../database/utils';
import { internalFindByIdsMapped } from '../../database/middleware-loader';
import { extractRepresentative } from '../../database/entity-representative';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../utils/access';

// ==================================================================
// Need a specific utils file to those functions because
// getMandatoryAttributesForSetting() is called inside middleware.ts,
// and so we have a cycle dependency if writing it inside .-domain.ts
// ==================================================================

// Fetch the schemas attributes for an entity setting and extend them with
// what is saved in this entity setting.
export const getEntitySettingSchemaAttributes = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting,
): Promise<EntitySettingSchemaAttribute[]> => {
  return telemetry(context, user, 'ATTRIBUTES', {
    [SEMATTRS_DB_NAME]: 'attributes_domain',
    [SEMATTRS_DB_OPERATION]: 'attributes_definition',
  }, async () => {
    if (!entitySetting) {
      return [];
    }
    const { target_type } = entitySetting;
    const attributesDefinition = schemaAttributesDefinition.getAttributes(target_type);
    const refsDefinition = schemaRelationsRefDefinition.getRelationsRef(target_type);
    const refsNames = schemaRelationsRefDefinition.getInputNames(target_type);

    const schemaAttributes: EntitySettingSchemaAttribute[] = [
      // Configs for attributes definition
      ...Array.from(attributesDefinition.values())
        .filter((attr: AttributeDefinition) => (
          attr.editDefault
          || attr.mandatoryType === 'external'
          || attr.mandatoryType === 'customizable'
        ))
        .map((attr) => ({
          name: attr.name,
          label: attr.label,
          type: attr.type,
          mandatoryType: attr.mandatoryType,
          editDefault: attr.editDefault,
          multiple: attr.multiple,
          mandatory: attr.mandatoryType === 'external',
          upsert: attr.upsert || false,
          scale: (attr.type === 'numeric' && attr.scalable) ? defaultScale : undefined,
        })),
      // Configs for refs definition
      ...Array.from(refsDefinition.values())
        .filter((ref: RefAttribute) => (
          ref.mandatoryType === 'external'
          || ref.mandatoryType === 'customizable'
        ))
        .map((ref) => ({
          name: ref.name,
          label: ref.label,
          editDefault: ref.editDefault,
          type: 'ref',
          mandatoryType: ref.mandatoryType,
          multiple: ref.multiple,
          mandatory: ref.mandatoryType === 'external',
          upsert: ref.upsert || false,
        })),
    ];

    // Used to resolve later default values ref with ids.
    const attributesDefaultValuesToResolve: Record<number, string[]> = {};

    // Extend schema attributes with entity settings data.
    getAttributesConfiguration(entitySetting)?.forEach((userDefinedAttr) => {
      const schemaIndex = schemaAttributes.findIndex((a) => a.name === userDefinedAttr.name);
      if (schemaIndex > -1) {
        const schemaAttribute = schemaAttributes[schemaIndex];
        if (schemaAttribute) {
          if (schemaAttribute.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
            schemaAttribute.mandatory = userDefinedAttr.mandatory;
          }
          if (isNotEmptyField(userDefinedAttr.default_values)) {
            schemaAttribute.defaultValues = (userDefinedAttr.default_values as string[])?.map((v) => ({ id: v, name: v }));
            // If the default value is a ref with an id, save it to resolve it below.
            if (schemaAttribute.name !== 'objectMarking' && refsNames.includes(schemaAttribute.name)) {
              attributesDefaultValuesToResolve[schemaIndex] = userDefinedAttr.default_values ?? [];
            }
          }
          if (schemaAttribute.scale && isNotEmptyField(userDefinedAttr.scale)) {
            // override default scale
            schemaAttribute.scale = JSON.stringify(userDefinedAttr.scale);
          }
        }
      }
    });

    // Resolve default values ref ids
    const idsToResolve = Object.values(attributesDefaultValuesToResolve).flat();
    const entities = await internalFindByIdsMapped(context, user, idsToResolve);
    Object.keys(attributesDefaultValuesToResolve).forEach((index) => {
      const defaultValues = schemaAttributes[Number(index)]?.defaultValues;
      if (defaultValues) {
        schemaAttributes[Number(index)].defaultValues = defaultValues.map((val) => {
          const entity = entities[val.id];
          return {
            id: val.id,
            name: entity ? (extractRepresentative(entity).main ?? val.id) : val.id,
          };
        });
      }
    });

    return schemaAttributes;
  });
};

export const getMandatoryAttributesForSetting = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting,
) => {
  const attributes = await getEntitySettingSchemaAttributes(context, user, entitySetting);
  if (isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS)) {
    return attributes.filter((a) => a.mandatory && a.mandatoryType !== 'customizable').map((a) => a.name);
  }
  return attributes.filter((a) => a.mandatory).map((a) => a.name);
};
