import Ajv from 'ajv';
import { isJsonAttribute, schemaAttributesDefinition } from './schema-attributes';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isNotEmptyField } from '../database/utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from './validator-register';
import type { AuthContext, AuthUser } from '../types/user';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { externalReferences } from './stixMetaRelationship';

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --

const validateFormatSchemaAttributes = (instanceType: string, input: Record<string, unknown>) => {
  const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);

  const inputEntries = Object.entries(input);
  inputEntries.forEach(([key, value]) => {
    if (isJsonAttribute(key)) {
      const attribute = availableAttributes.find((attr) => attr.name === key);
      if (!attribute) {
        throw ValidationError(
          key,
          { message: 'This attribute is not declared for this type', data: { attribute: key, entityType: instanceType } }
        );
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

const validateMandatoryAttributesOnCreation = (
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  // Should have all the mandatory keys and the associated values not null
  const inputValidValue = (inputKeys: string[], mandatoryKey: string) => (inputKeys.includes(mandatoryKey)
    && (Array.isArray(input[mandatoryKey]) ? (input[mandatoryKey] as []).some((i: string) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));

  validateMandatoryAttributes(input, entitySetting, true, inputValidValue);
};
const validateMandatoryAttributesOnUpdate = (
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  // If the mandatory key is present the associated value should be not null
  const inputValidValue = (inputKeys: string[], mandatoryKey: string) => (!inputKeys.includes(mandatoryKey)
    || (Array.isArray(input[mandatoryKey]) ? (input[mandatoryKey] as []).some((i: string) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));

  validateMandatoryAttributes(input, entitySetting, false, inputValidValue);
};

export const validateInputCreation = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
) => {
  // Generic validator
  validateFormatSchemaAttributes(instanceType, input);
  validateMandatoryAttributesOnCreation(input, entitySetting);

  // Functional validator
  const validator = getEntityValidatorCreation(instanceType);

  if (validator) {
    const validate = await validator(input);
    if (!validate) {
      throw UnsupportedError('The input is not valid', { input });
    }
  }
};

export const validateInputUpdate = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Array<unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  initial: Record<string, unknown>
) => {
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
  validateFormatSchemaAttributes(instanceType, inputs);
  validateMandatoryAttributesOnUpdate(inputs, entitySetting);

  // Functional validator
  const validator = getEntityValidatorUpdate(instanceType);

  if (validator) {
    const validate = await validator(inputs, initial);
    if (!validate) {
      throw UnsupportedError('The input is not valid', { inputs });
    }
  }
};
