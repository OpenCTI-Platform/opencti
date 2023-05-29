import Ajv from 'ajv';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { isJsonAttribute, schemaAttributesDefinition } from './schema-attributes';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isNotEmptyField } from '../database/utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from './validator-register';
import type { AuthContext, AuthUser } from '../types/user';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { externalReferences } from './stixRefRelationship';
import { telemetry } from '../config/tracing';

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --

const validateFormatSchemaAttributes = async (context: AuthContext, user: AuthUser, instanceType: string, input: Record<string, unknown>) => {
  const validateFormatSchemaAttributesFn = async () => {
    const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);
    const inputEntries = Object.entries(input);
    inputEntries.forEach(([key, value]) => {
      if (isJsonAttribute(key)) {
        const attribute = availableAttributes.get(key);
        if (!attribute) {
          throw ValidationError(key, {
            message: 'This attribute is not declared for this type',
            data: { attribute: key, entityType: instanceType }
          });
        }
        if (attribute.schemaDef) {
          const validate = ajv.compile(attribute.schemaDef);
          const valid = validate(JSON.parse(value as string));
          if (!valid) {
            throw ValidationError(key, { message: 'The JSON Schema is not valid', data: validate.errors });
          }
        }
      }
    });
  };
  return telemetry(context, user, 'SCHEMA ATTRIBUTES VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'schema',
  }, validateFormatSchemaAttributesFn);
};

// -- VALIDATE ATTRIBUTE MANDATORY --

const validateMandatoryAttributes = (
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  isCreation: boolean,
  validation: (inputKeys: string[], mandatoryKey: string) => boolean
) => {
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (!attributesConfiguration) {
    return;
  }
  const mandatoryAttributes = attributesConfiguration.filter((attr) => attr.mandatory);
  // In creation if enforce reference is activated, user must provide a least 1 external references
  if (isCreation && entitySetting.enforce_reference === true) {
    mandatoryAttributes.push({ name: externalReferences.inputName, mandatory: true });
  }
  const inputKeys = Object.keys(input);
  mandatoryAttributes.forEach((attr) => {
    if (!(validation(inputKeys, attr.name))) {
      throw ValidationError(attr.name, { message: 'This attribute is mandatory', attribute: attr.name });
    }
  });
};

const validateMandatoryAttributesOnCreation = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  const validateMandatoryAttributesOnCreationFn = async () => {
    // Should have all the mandatory keys and the associated values not null
    const inputValidValue = (inputKeys: string[], mandatoryKey: string) => (inputKeys.includes(mandatoryKey)
        && (Array.isArray(input[mandatoryKey]) ? (input[mandatoryKey] as []).some((i: string) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));

    validateMandatoryAttributes(input, entitySetting, true, inputValidValue);
  };
  return telemetry(context, user, 'MANDATORY CREATION VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'mandatory',
  }, validateMandatoryAttributesOnCreationFn);
};
const validateMandatoryAttributesOnUpdate = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  const validateMandatoryAttributesOnUpdateFn = async () => {
    // If the mandatory key is present the associated value should be not null
    const inputValidValue = (inputKeys: string[], mandatoryKey: string) => (!inputKeys.includes(mandatoryKey)
        || (Array.isArray(input[mandatoryKey]) ? (input[mandatoryKey] as []).some((i: string) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));

    validateMandatoryAttributes(input, entitySetting, false, inputValidValue);
  };
  return telemetry(context, user, 'MANDATORY UPDATE VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'mandatory',
  }, validateMandatoryAttributesOnUpdateFn);
};

export const validateInputCreation = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
) => {
  const validateInputCreationFn = async () => {
    // Generic validator
    await validateFormatSchemaAttributes(context, user, instanceType, input);
    await validateMandatoryAttributesOnCreation(context, user, input, entitySetting);
    // Functional validator
    const validator = getEntityValidatorCreation(instanceType);
    if (validator) {
      const validate = await validator(input);
      if (!validate) {
        throw UnsupportedError('The input is not valid', { input });
      }
    }
  };
  return telemetry(context, user, 'CREATION VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'creation',
  }, validateInputCreationFn);
};

const validateUpdatableAttribute = (instanceType: string, input: Record<string, unknown>) => {
  Object.entries(input).forEach(([key]) => {
    const attribute = schemaAttributesDefinition.getAttribute(instanceType, key);
    if (attribute?.update === false) {
      throw ValidationError(attribute.name, { message: `You cannot update ${attribute.name} attribute` });
    }
  });
};

export const validateInputUpdate = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Array<unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  initial: Record<string, unknown>
) => {
  const validateInputUpdateFn = async () => {
    // Convert input to record
    let inputs: Record<string, unknown> = {};
    if (Array.isArray(input)) {
      input.forEach((obj) => {
        inputs[obj.key] = obj.value;
      });
    } else {
      inputs = input;
    }
    // Generic validator
    await validateFormatSchemaAttributes(context, user, instanceType, inputs);
    await validateMandatoryAttributesOnUpdate(context, user, inputs, entitySetting);
    validateUpdatableAttribute(instanceType, inputs);
    // Functional validator
    const validator = getEntityValidatorUpdate(instanceType);
    if (validator) {
      const validate = await validator(inputs, initial);
      if (!validate) {
        throw UnsupportedError('The input is not valid', { inputs });
      }
    }
  };
  return telemetry(context, user, 'UPDATE VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'update',
  }, validateInputUpdateFn);
};
