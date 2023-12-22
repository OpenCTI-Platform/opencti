import * as R from 'ramda';
import Ajv from 'ajv';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import {
  isBooleanAttribute,
  isDateAttribute,
  isDictionaryAttribute,
  isJsonAttribute,
  isNumericAttribute,
  isStringAttribute,
  schemaAttributesDefinition
} from './schema-attributes';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isNotEmptyField } from '../database/utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from './validator-register';
import type { AuthContext, AuthUser } from '../types/user';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { externalReferences } from './stixRefRelationship';
import { telemetry } from '../config/tracing';
import type { AttributeDefinition } from './attribute-definition';
import type { EditInput } from '../generated/graphql';
import { EditOperation } from '../generated/graphql';
import { utcDate } from '../utils/format';

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --
export const validateAndFormatSchemaAttribute = (
  instanceType: string,
  attributeName: string,
  attributeDefinition: AttributeDefinition | undefined,
  initial: object,
  editInput: EditInput
) => {
  // Complex object must be completely enforced
  if (isJsonAttribute(attributeName)) {
    if (!attributeDefinition) {
      throw ValidationError(attributeName, {
        message: 'This attribute is not declared for this type',
        data: { attribute: attributeName, entityType: instanceType }
      });
    }
    if (attributeDefinition.type === 'json' && attributeDefinition.schemaDef) {
      const validate = ajv.compile(attributeDefinition.schemaDef);
      const jsonValue = R.head(editInput.value); // json cannot be multiple
      const valid = validate(JSON.parse(jsonValue as string));
      if (!valid) {
        throw ValidationError(attributeName, { message: 'The JSON schema is not valid', data: validate.errors });
      }
    }
  }
  // Simple object must be eventually tested as the model is not complete yet
  if (attributeDefinition && editInput.value) {
    // Test multiple for all types
    if (!attributeDefinition.multiple && editInput.value.length > 1) {
      throw ValidationError(attributeName, { message: `Attribute ${attributeName} cannot be multiple`, data: editInput });
    }
    // Test string value
    if (isStringAttribute(attributeName)) {
      const values = [];
      for (let index = 0; index < editInput.value.length; index += 1) {
        const value = editInput.value[index];
        if (value && !R.is(String, value)) {
          throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a string`, data: editInput });
        } else {
          values.push(value ? value.trim() : value);
        }
      }
      // This is reference change to trim the input and prevent unuseful stream events
      // TODO Find a better way to rework the data
      // eslint-disable-next-line no-param-reassign
      editInput.value = values;
    }
    // Test boolean value (Accept string)
    if (isBooleanAttribute(attributeName)) {
      editInput.value.forEach((value) => {
        if (value && !R.is(Boolean, value) && !R.is(String, value)) {
          throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a boolean/string`, data: editInput });
        }
      });
    }
    // Test date value (Accept only ISO date string)
    if (isDateAttribute(attributeName)) {
      editInput.value.forEach((value) => {
        if (value && !R.is(String, value) && !utcDate(value).isValid()) {
          throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a boolean/string`, data: editInput });
        }
      });
    }
    // Test numeric value (Accept string)
    if (isNumericAttribute(attributeName)) {
      editInput.value.forEach((value) => {
        if (value && Number.isNaN(Number(value))) {
          throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a numeric/string`, data: editInput });
        }
      });
    }
    // Test dictionary (partial patch only with string)
    if (isDictionaryAttribute(attributeName)) {
      editInput.value.forEach((value) => {
        if (editInput.key.includes('.')) { // Partial patch, must be a string for now
          if (value && !R.is(String, value)) {
            throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a string`, data: editInput });
          }
        } else if (value && !R.is(Object, value) && Object.keys(value).length === 0) { // Complete patch, must be an object
          throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be an object`, data: editInput });
        }
      });
    }
  }
};

const validateFormatSchemaAttributes = async (context: AuthContext, user: AuthUser, instanceType: string, initial: Record<string, unknown>, editInputs: EditInput[]) => {
  const validateFormatSchemaAttributesFn = async () => {
    const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);
    editInputs.forEach((editInput) => {
      const attributeDefinition = availableAttributes.get(editInput.key);
      validateAndFormatSchemaAttribute(instanceType, editInput.key, attributeDefinition, initial, editInput);
    });
  };
  return telemetry(context, user, 'SCHEMA ATTRIBUTES VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'schema_attributes',
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
  if (isCreation && entitySetting.enforce_reference) {
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
    const editInputs: EditInput[] = Object.entries(input)
      .map(([k, v]) => ({ operation: EditOperation.Replace, value: Array.isArray(v) ? v : [v], key: k }));
    await validateFormatSchemaAttributes(context, user, instanceType, input, editInputs);
    await validateMandatoryAttributesOnCreation(context, user, input, entitySetting);
    // Functional validator
    const validator = getEntityValidatorCreation(instanceType);
    if (validator) {
      const validate = await validator(context, user, input);
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
  initial: Record<string, unknown>,
  editInputs: EditInput[],
  entitySetting: BasicStoreEntityEntitySetting,
) => {
  const validateInputUpdateFn = async () => {
    // Convert input to record
    const instanceFromInputs: Record<string, unknown> = {};
    editInputs.forEach((obj) => { instanceFromInputs[obj.key] = obj.value; });
    // Generic validator
    await validateFormatSchemaAttributes(context, user, instanceType, initial, editInputs);
    await validateMandatoryAttributesOnUpdate(context, user, instanceFromInputs, entitySetting);
    validateUpdatableAttribute(instanceType, instanceFromInputs);
    // Functional validator
    const validator = getEntityValidatorUpdate(instanceType);
    if (validator) {
      const validate = await validator(context, user, instanceFromInputs, initial);
      if (!validate) {
        throw UnsupportedError('The input is not valid', { inputs: instanceFromInputs });
      }
    }
  };
  return telemetry(context, user, 'UPDATE VALIDATION', {
    [SemanticAttributes.DB_NAME]: 'validation',
    [SemanticAttributes.DB_OPERATION]: 'update',
  }, validateInputUpdateFn);
};
