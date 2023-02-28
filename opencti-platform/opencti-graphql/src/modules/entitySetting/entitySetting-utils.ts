import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT
} from '../../schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { getParentTypes } from '../../schema/schemaUtils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { UnsupportedError, ValidationError } from '../../config/errors';
import type { AttributeConfiguration, BasicStoreEntityEntitySetting, ConfidenceScale } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getEntitiesFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { RelationRefDefinition } from '../../schema/relationRef-definition';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';

export type typeAvailableSetting = boolean | string;

export const defaultEntitySetting: Record<string, typeAvailableSetting> = {
  platform_entity_files_ref: false,
  platform_hidden_type: false,
  enforce_reference: false,
  attributes_configuration: JSON.stringify([]),
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
  platform_entity_files_ref: [ABSTRACT_STIX_DOMAIN_OBJECT],
  platform_hidden_type: [ABSTRACT_STIX_DOMAIN_OBJECT],
  attributes_configuration: [ABSTRACT_STIX_DOMAIN_OBJECT],
  enforce_reference: [
    ENTITY_TYPE_ATTACK_PATTERN,
    ENTITY_TYPE_CAMPAIGN,
    ENTITY_TYPE_CHANNEL,
    ENTITY_TYPE_LOCATION_CITY,
    ENTITY_TYPE_LOCATION_COUNTRY,
    ENTITY_TYPE_COURSE_OF_ACTION,
    ENTITY_TYPE_DATA_COMPONENT,
    ENTITY_TYPE_DATA_SOURCE,
    ENTITY_TYPE_EVENT,
    ENTITY_TYPE_CONTAINER_GROUPING,
    ENTITY_TYPE_INCIDENT,
    ENTITY_TYPE_INDICATOR,
    ENTITY_TYPE_IDENTITY_INDIVIDUAL,
    ENTITY_TYPE_INFRASTRUCTURE,
    ENTITY_TYPE_INTRUSION_SET,
    ENTITY_TYPE_MALWARE,
    ENTITY_TYPE_NARRATIVE,
    ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
    ENTITY_TYPE_IDENTITY_ORGANIZATION,
    ENTITY_TYPE_LOCATION_POSITION,
    ENTITY_TYPE_LOCATION_REGION,
    ENTITY_TYPE_CONTAINER_REPORT,
    ENTITY_TYPE_IDENTITY_SECTOR,
    ENTITY_TYPE_IDENTITY_SYSTEM,
    ENTITY_TYPE_THREAT_ACTOR,
    ENTITY_TYPE_TOOL,
    ENTITY_TYPE_VULNERABILITY,
  ],
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

const keyAvailableSetting = R.uniq(Object.keys(availableSettings).flat());

export const getAvailableSettings = (targetType: string): string[] => {
  const entityTypes = [targetType, ...getParentTypes(targetType)];
  // TODO: Need to refacto this method
  if (entityTypes.some((e) => [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP].includes(e))) {
    return [];
  }
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

export const validateEntitySettingCreation = async (input: Record<string, unknown>) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(entitySetting.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySetting.target_type, entitySetting);
  confidenceScaleValidation(entitySetting);

  return true;
};

export const validateEntitySettingUpdate = async (input: Record<string, unknown>, initial: Record<string, unknown> | undefined) => {
  const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);
  const entitySettingInitial = (initial as unknown as BasicStoreEntityEntitySetting);

  await optionsValidation(entitySettingInitial.target_type, input as unknown as BasicStoreEntityEntitySetting);
  customizableAttributesValidation(entitySettingInitial.target_type, entitySetting);
  confidenceScaleValidation(entitySetting);

  return true;
};

// -- AJV --

export const attributeConfiguration: JSONSchemaType<AttributeConfiguration[]> = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1 },
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
            color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
            label: { type: 'string', minLength: 1 },
          },
          required: ['value', 'color', 'label'],
        },
        max: {
          type: 'object',
          properties: {
            value: { type: 'number' },
            color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
            label: { type: 'string', minLength: 1 },
          },
          required: ['value', 'color', 'label'],
        },
        ticks: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              value: { type: 'number' },
              color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
              label: { type: 'string', minLength: 1 },
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
