import * as R from 'ramda';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { UnsupportedError, ValidationError } from '../../config/errors';
import type { BasicStoreEntityEntitySetting, Scale } from './entitySetting-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { validateAndFormatSchemaAttribute } from '../../schema/schema-validator';
import { availableSettings, getAttributesConfiguration, getAvailableSettings, getDefaultValues } from './entitySetting-utils';
import { telemetry } from '../../config/tracing';
import { INPUT_MARKINGS } from '../../schema/general';
import type { EditInput } from '../../generated/graphql';
import { EditOperation } from '../../generated/graphql';

const keyAvailableSetting = R.uniq(Object.values(availableSettings).flat());

// -- VALIDATORS --

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

export const validateSetting = (typeId: string, setting: string) => {
  const settings = getAvailableSettings(typeId);
  if (!settings.includes(setting)) {
    throw UnsupportedError('This setting is not available for this entity', {
      setting,
      entity: typeId
    });
  }
};

const scaleValidation = (scale: Scale) => {
  if (scale?.local_config) {
    const minValue = scale.local_config.min.value;
    const maxValue = scale.local_config.max.value;
    const valuesOfTick = scale.local_config.ticks.sort().map(({ value }) => value);
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
    valuesOfTick.forEach((tick) => {
      if (tick < minValue || tick > maxValue) {
        throw ValidationError(tick, {
          message: 'Each tick value must be between min and max value'
        });
      }
    });
  }
};

const attributesConfigurationValidation = async (context: AuthContext, user: AuthUser, targetType: string, input: BasicStoreEntityEntitySetting) => {
  const attributesConfiguration = getAttributesConfiguration(input);
  if (attributesConfiguration) {
    for (let index = 0; index < attributesConfiguration.length; index += 1) {
      const attr = attributesConfiguration[index];
      const attributeDefinition = schemaAttributesDefinition.getAttribute(targetType, attr.name);
      const relationRefDefinition = schemaRelationsRefDefinition.getRelationRef(targetType, attr.name);
      // Mandatory
      if (attr.mandatory) {
        const mandatoryType = attributeDefinition?.mandatoryType || relationRefDefinition?.mandatoryType;
        if (mandatoryType !== 'customizable') {
          throw ValidationError(attr.name, {
            message: 'This attribute is not customizable for this entity',
            data: { attribute: attr.name, entityType: targetType }
          });
        }
      }
      // Scale
      if (attr.scale) {
        // Relation ref can't be scalable
        if (attributeDefinition?.type === 'numeric' && !attributeDefinition?.scalable) {
          throw ValidationError(attr.name, {
            message: 'This attribute is not scalable for this entity',
            data: { attribute: attr.name, entityType: targetType }
          });
        }
        scaleValidation(attr.scale);
      }
      // Default values
      if (attr.default_values) {
        if (attributeDefinition) {
          const defaultValues = getDefaultValues(attr, attributeDefinition.multiple);
          if (defaultValues) {
            const checkValues = Array.isArray(defaultValues) ? defaultValues : [defaultValues];
            const checkInput: EditInput = { operation: EditOperation.Replace, key: attributeDefinition.name, value: checkValues };
            validateAndFormatSchemaAttribute(attr.name, attributeDefinition, checkInput);
          }
        } else if (relationRefDefinition) {
          if (relationRefDefinition.name === INPUT_MARKINGS) {
            if (getDefaultValues(attr, false) !== 'false' && getDefaultValues(attr, false) !== 'true') {
              throw ValidationError(attr.name, {
                message: 'This field is not supported to declare a default value. You can only activate/deactivate the possibility to have a default value.',
                data: { attribute: attr.name, entityType: targetType }
              });
            } else {
              return;
            }
          }
        }
      }
    }
  }
};

export const validateEntitySettingCreation = async (context: AuthContext, user: AuthUser, input: Record<string, unknown>) => {
  const validateEntitySettingUpdateFn = async () => {
    const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);

    await optionsValidation(entitySetting.target_type, input as unknown as BasicStoreEntityEntitySetting);
    await attributesConfigurationValidation(context, user, entitySetting.target_type, entitySetting);

    return true;
  };

  return telemetry(context, user, 'ENTITY SETTING CREATION VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'entity-setting',
    [SemanticAttributes.DB_OPERATION]: 'validation_update',
  }, validateEntitySettingUpdateFn);
};

export const validateEntitySettingUpdate = async (context: AuthContext, user: AuthUser, input: Record<string, unknown>, initial: Record<string, unknown> | undefined) => {
  const validateEntitySettingUpdateFn = async () => {
    const entitySetting = (input as unknown as BasicStoreEntityEntitySetting);
    const entitySettingInitial = (initial as unknown as BasicStoreEntityEntitySetting);

    await optionsValidation(entitySettingInitial.target_type, input as unknown as BasicStoreEntityEntitySetting);
    await attributesConfigurationValidation(context, user, entitySettingInitial.target_type, entitySetting);

    return true;
  };

  return telemetry(context, user, 'ENTITY SETTING UPDATE VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'entity-setting',
    [SemanticAttributes.DB_OPERATION]: 'validation_update',
  }, validateEntitySettingUpdateFn);
};
