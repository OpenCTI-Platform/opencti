import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT
} from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_TOOL, ENTITY_TYPE_VULNERABILITY,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { getParentTypes } from '../../schema/schemaUtils';
import { UnsupportedError, ValidationError } from '../../config/errors';
import type { AttributeConfiguration, BasicStoreEntityEntitySetting, ConfidenceScale } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getEntitiesFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { schemaDefinition } from '../../schema/schema-register';

export const defaultEntitySetting: Record<string, boolean | string> = {
  platform_entity_files_ref: false,
  platform_hidden_type: false,
  enforce_reference: false,
  confidence_scale: JSON.stringify({
    localConfig: {
      better_side: 'min',
      min: {
        value: 0,
        color: '#f44336',
        label: 'Low',
      },
      max: {
        value: 100,
        color: '#4caf50',
        label: 'High',
      },
      ticks: [
        { value: 40, color: '#ff9800', label: 'Moderate' },
        { value: 60, color: '#5c7bf5', label: 'Good' },
        { value: 80, color: '#4caf50', label: 'Strong' },
      ],
    }
  })
};

export const availableSettings: Record<string, Array<string>> = {
  platform_entity_files_ref: [ABSTRACT_STIX_DOMAIN_OBJECT, STIX_SIGHTING_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE],
  platform_hidden_type: [ABSTRACT_STIX_DOMAIN_OBJECT],
  enforce_reference: [ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP],
  attributes_configuration: [ENTITY_TYPE_DATA_COMPONENT],
  confidence_scale: [
    ENTITY_TYPE_CONTAINER_REPORT,
    ENTITY_TYPE_CONTAINER_GROUPING,
    ENTITY_TYPE_CONTAINER_NOTE,
    ENTITY_TYPE_CONTAINER_OPINION,
    ENTITY_TYPE_CONTAINER_CASE,
    ENTITY_TYPE_INCIDENT,
    ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
    ENTITY_TYPE_INDICATOR,
    ENTITY_TYPE_INFRASTRUCTURE,
    ENTITY_TYPE_THREAT_ACTOR,
    ENTITY_TYPE_INTRUSION_SET,
    ENTITY_TYPE_CAMPAIGN,
    ENTITY_TYPE_MALWARE,
    ENTITY_TYPE_CHANNEL,
    ENTITY_TYPE_TOOL,
    ENTITY_TYPE_VULNERABILITY,
    ENTITY_TYPE_DATA_SOURCE,
    ENTITY_TYPE_DATA_COMPONENT,
    STIX_SIGHTING_RELATIONSHIP,
  ],
};

const typeAvailableSetting = R.uniq(Object.values(availableSettings).flat());

export const getAvailableSettings = (targetType: string): string[] => {
  const entityTypes = [targetType, ...getParentTypes(targetType)];
  const availableKeys = Object.keys(availableSettings);
  const settings = availableKeys.filter((availableKey) => {
    const compatibleTypes = availableSettings[availableKey];
    return entityTypes.some((e) => compatibleTypes.includes(e));
  });
  if (settings.length === 0) {
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

export const getConfidenceScale = (entitySetting: BasicStoreEntityEntitySetting) => {
  if (entitySetting?.confidence_scale) {
    return JSON.parse(entitySetting.confidence_scale) as ConfidenceScale;
  }
  return null;
};

// -- VALIDATOR --

const optionsValidation = async (context: AuthContext, user: AuthUser, targetType: string, input: BasicStoreEntityEntitySetting) => {
  const settings = getAvailableSettings(targetType);
  const inputSettings = Object.entries(input);
  inputSettings.forEach(([key]) => {
    if (typeAvailableSetting.includes(key) && !settings.includes(key)) {
      throw UnsupportedError('This setting is not available for this entity', {
        setting: key,
        entity: targetType
      });
    }
  });
};

const customizableAttributesValidation = (entitySetting: BasicStoreEntityEntitySetting) => {
  const attributesConfiguration = getAttributesConfiguration(entitySetting);

  if (attributesConfiguration) {
    const customizableMandatoryAttributeNames = schemaDefinition.getAttributes(entitySetting.target_type)
      .filter((attr) => attr.mandatoryType === 'customizable')
      .map((attr) => attr.name);

    attributesConfiguration.forEach((attr) => {
      if (attr.mandatory && !customizableMandatoryAttributeNames.includes(attr.name)) {
        throw ValidationError(attr.name, {
          message: 'This attribute is not customizable for this entity',
          data: { attribute: attr.name, entityType: entitySetting.target_type }
        });
      }
    });
  }
};

const confidenceScaleValidation = (entitySetting: BasicStoreEntityEntitySetting) => {
  const confidenceScaleConfiguration: ConfidenceScale | null = getConfidenceScale(entitySetting);

  if (confidenceScaleConfiguration?.localConfig) {
    const { min, max } = confidenceScaleConfiguration.localConfig;
    const minValue = min.value;
    const maxValue = max.value;
    const getValuesOfTick = confidenceScaleConfiguration.localConfig.ticks.sort().map(({ value }) => value);
    if (minValue < 0 || minValue > 100) {
      throw ValidationError(minValue, {
        message: 'The min value must be between 0 and 100',
      });
    } else if (maxValue > 100 || maxValue < 0) {
      throw ValidationError(maxValue, {
        message: 'The max value must be between 0 and 100',
      });
    }
    if (minValue > maxValue) {
      throw ValidationError(minValue, {
        message: 'The min value cannot be greater than max value'
      });
    } else if (maxValue < minValue) {
      throw ValidationError(maxValue, {
        message: 'The max value cannot be lower than min value'
      });
    }
    getValuesOfTick.forEach((tick) => {
      if (tick < minValue || tick > maxValue) {
        throw ValidationError(tick, {
          message: 'Each tick value must be between min and max value'
        });
      }
    });
  }
};

export const validateEntitySettingCreation = async (context: AuthContext, user: AuthUser, input: Record<string, unknown>) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(context, user, entitySetting.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySetting);
  confidenceScaleValidation(entitySetting);

  return true;
};

export const validateEntitySettingUpdate = async (context: AuthContext, user: AuthUser, input: Record<string, unknown>, initial: Record<string, unknown> | undefined) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);
  const entitySettingInitial = (initial as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(context, user, entitySettingInitial.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySetting);
  confidenceScaleValidation(entitySetting);

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

export const confidenceScale: JSONSchemaType<ConfidenceScale> = {
  type: 'object',
  properties: {
    localConfig: {
      type: 'object',
      properties: {
        better_side: { type: 'string' },
        min: {
          type: 'object',
          properties: {
            value: { type: 'number' },
            color: { type: 'string' },
            label: { type: 'string' },
          },
          required: ['value', 'color', 'label'],
        },
        max: {
          type: 'object',
          properties: {
            value: { type: 'number' },
            color: { type: 'string' },
            label: { type: 'string' },
          },
          required: ['value', 'color', 'label'],
        },
        ticks: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              value: { type: 'number' },
              color: { type: 'string' },
              label: { type: 'string' },
            },
            required: ['value', 'color', 'label'],
          }
        },
      },
      required: ['min', 'max'],
    },
  },
  required: ['localConfig']
};
