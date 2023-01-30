import Ajv from 'ajv';
import { isJsonAttr, schemaDefinition } from '../schema/schema-register';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isEmptyField, isNotEmptyField } from './utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from '../schema/validator-register';
import type { AuthContext, AuthUser } from '../types/user';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --

const validateSchemaAttributes = (instanceType: string, input: Record<string, unknown>) => {
  const availableAttributes = schemaDefinition.getAttributes(instanceType);
  const availableAttributeNames = availableAttributes.map((attr) => attr.name);
  if (isEmptyField(availableAttributes)) {
    return; // TODO: need to migrate all the elements first
  }

  const inputEntries = Object.entries(input);
  inputEntries.forEach(([key, value]) => {
    if (!availableAttributeNames.includes(key)) {
      throw ValidationError(
        key,
        { message: 'This attribute is not declared for this type', data: { attribute: key, entityType: instanceType } }
      );
    }

    if (isJsonAttr(key)) {
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
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  validation: (inputKeys: string[], mandatoryKey: string) => boolean
) => {
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (!attributesConfiguration) {
    return;
  }

  const mandatoryAttributes = attributesConfiguration.filter((attr) => attr.mandatory);
  const inputKeys = Object.keys(input);

  mandatoryAttributes.forEach((attr) => {
    if (!(validation(inputKeys, attr.name))) {
      throw ValidationError(attr.name, { message: 'This attribute is mandatory', attribute: attr.name });
    }
  });
};

const validateMandatoryAttributesOnCreation = (
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  // Should have all the mandatory keys and the associated values not null
  const inputValidValue = (inputKeys: string[], mandatoryKey: string) => inputKeys.includes(mandatoryKey) && isNotEmptyField(input[mandatoryKey]);

  validateMandatoryAttributes(instanceType, input, entitySetting, inputValidValue);
};
const validateMandatoryAttributesOnUpdate = (
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  // If the mandatory key is present the associated value should be not null
  const inputValidValue = (inputKeys: string[], mandatoryKey: string) => !inputKeys.includes(mandatoryKey) || isNotEmptyField(input[mandatoryKey]);

  validateMandatoryAttributes(instanceType, input, entitySetting, inputValidValue);
};

export const validateInputCreation = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
) => {
  // Generic validator
  validateSchemaAttributes(instanceType, input);
  validateMandatoryAttributesOnCreation(instanceType, input, entitySetting);

  // Functional validator
  const validator = getEntityValidatorCreation(instanceType);

  if (validator) {
    const validate = await validator(context, user, input);
    if (!validate) {
      throw UnsupportedError('The input is not valid', { input });
    }
  }
};

export const validateInputUpdate = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  initial: Record<string, unknown>
) => {
  // Generic validator
  validateSchemaAttributes(instanceType, input);
  validateMandatoryAttributesOnUpdate(instanceType, input, entitySetting);

  // Functional validator
  const validator = getEntityValidatorUpdate(instanceType);

  if (validator) {
    const validate = await validator(context, user, input, initial);
    if (!validate) {
      throw UnsupportedError('The input is not valid', { input });
    }
  }
};
