import { schemaAttributesDefinition } from '../schema/schema-attributes';
import type { AuthContext } from '../types/user';
import { INTERNAL_ATTRIBUTES, INTERNAL_REFS } from './attribute-utils';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { isNotEmptyField } from '../database/utils';

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

// -- ATTRIBUTES --

export const getSchemaAttributes = async (context: AuthContext, entityType: string) => {
  // Handle attributes
  const managed_internal_attributes = [...INTERNAL_ATTRIBUTES,
    'created_by_ref',
    'current_state_cursor',
    'event_types',
    'feed_attributes',
    'instance_trigger',
    'notifier_connector_id',
    'object_marking_refs',
    'outcomes',
    'playbook_definition',
    'playbook_start',
    'report_types',
    'template_id',
    'updated',
    'type',
  ];
  const mapAttributes = schemaAttributesDefinition.getAttributes(entityType);
  const resultAttributes: AttributeConfigMeta[] = Array.from(mapAttributes.values())
    .filter((attribute) => !managed_internal_attributes.includes(attribute.name))
    .map((attribute) => ({
      ...attribute,
      mandatory: ['external', 'internal'].includes(attribute.mandatoryType),
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
  results.sort((a, b) => ((a.name > b.name) ? 1 : -1));
  return results;
};

export const getSchemaAttributesAll = async (context: AuthContext, entityType: string) => {
  // Handle attributes
  const mapAttributes = schemaAttributesDefinition.getAttributes(entityType);
  const results: AttributeConfigMeta[] = Array.from(mapAttributes.values())
    .map((attribute) => ({
      ...attribute,
      mandatory: attribute.mandatoryType !== 'no',
    }));
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
  results.sort((a, b) => ((a.name > b.name) ? 1 : -1));
  return results;
};
