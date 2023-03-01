import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT
} from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  isStixDomainObject
} from '../../schema/stixDomainObject';
import { UnsupportedError, ValidationError } from '../../config/errors';
import type { AttributeConfiguration, BasicStoreEntityEntitySetting } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getEntitiesFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { RelationRefDefinition } from '../../schema/relationRef-definition';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';

export type typeAvailableSetting = boolean | string;

export const defaultEntitySetting: Record<string, typeAvailableSetting> = {
  platform_entity_files_ref: false,
  platform_hidden_type: false,
  enforce_reference: false,
  attributes_configuration: JSON.stringify([]),
};

// Available settings works by override.
export const availableSettings: Record<string, Array<string>> = {
  [ABSTRACT_STIX_DOMAIN_OBJECT]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference'],
  [ABSTRACT_STIX_CYBER_OBSERVABLE]: ['platform_entity_files_ref'],
  [ABSTRACT_STIX_CORE_RELATIONSHIP]: [],
  [STIX_SIGHTING_RELATIONSHIP]: [],
  // enforce_reference not available on specific entities
  [ENTITY_TYPE_CONTAINER_NOTE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type'],
  [ENTITY_TYPE_CONTAINER_OPINION]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type'],
  [ENTITY_TYPE_CONTAINER_CASE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type'],
};

const keyAvailableSetting = R.uniq(Object.values(availableSettings).flat());

export const getAvailableSettings = (targetType: string) => {
  let settings;
  if (isStixDomainObject(targetType)) {
    settings = availableSettings[targetType] ?? availableSettings[ABSTRACT_STIX_DOMAIN_OBJECT];
  } else {
    settings = availableSettings[targetType];
  }

  if (!settings) {
    throw UnsupportedError('This entity type is not support for entity settings', { target_type: targetType });
  }

  return settings;
};

// -- HELPERS --

export const getEntitySettingFromCache = async (context: AuthContext, type: string) => {
  const entitySettings = await getEntitiesFromCache<BasicStoreEntityEntitySetting>(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
  let entitySetting = entitySettings.find((es) => es.target_type === type);

  if (!entitySetting) {
    // Inheritance
    if (isStixCoreRelationship(type)) {
      entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP);
    } else if (isStixCyberObservable(type)) {
      entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CYBER_OBSERVABLE);
    }
  }

  return entitySetting;
};

export const getAttributesConfiguration = (entitySetting: BasicStoreEntityEntitySetting) => {
  if (entitySetting?.attributes_configuration) {
    return JSON.parse(entitySetting.attributes_configuration as string) as AttributeConfiguration[];
  }
  return null;
};

// -- VALIDATOR --

const optionsValidation = async (targetType: string, input: BasicStoreEntityEntitySetting) => {
  const settings = getAvailableSettings(targetType);
  const inputSettings = Object.entries(input);
  inputSettings.forEach(([key]) => {
    if (keyAvailableSetting.includes(key) && !settings.includes(key)) {
      throw UnsupportedError('This setting is not available for this entity', {
        setting: key,
        entity: targetType
      });
    }
  });
};

const customizableAttributesValidation = (targetType: string, input: BasicStoreEntityEntitySetting) => {
  const attributesConfiguration = getAttributesConfiguration(input);

  if (attributesConfiguration) {
    const customizableMandatoryAttributeNames = schemaAttributesDefinition.getAttributes(targetType)
      .filter((attr) => attr.mandatoryType === 'customizable')
      .map((attr) => attr.name);

    // From schema relations ref
    const relationsRef: RelationRefDefinition[] = schemaRelationsRefDefinition.getRelationsRef(targetType);
    customizableMandatoryAttributeNames.push(...relationsRef.map((rel) => rel.inputName));

    attributesConfiguration.forEach((attr) => {
      if (attr.mandatory && !customizableMandatoryAttributeNames.includes(attr.name)) {
        throw ValidationError(attr.name, {
          message: 'This attribute is not customizable for this entity',
          data: { attribute: attr.name, entityType: targetType }
        });
      }
    });
  }
};

export const validateEntitySettingCreation = async (input: Record<string, unknown>) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(entitySetting.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySetting.target_type, entitySetting);

  return true;
};

export const validateEntitySettingUpdate = async (input: Record<string, unknown>, initial: Record<string, unknown> | undefined) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);
  const entitySettingInitial = (initial as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(entitySettingInitial.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySettingInitial.target_type, entitySetting);

  return true;
};

// -- AJV --

export const attributeConfiguration: JSONSchemaType<AttributeConfiguration[]> = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      name: { type: 'string' },
      mandatory: { type: 'boolean' }
    },
    required: ['name', 'mandatory']
  },
};
