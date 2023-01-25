import Ajv from 'ajv';
import { isJsonAttr, schemaDefinition } from '../schema/schema-register';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isEmptyField, isNotEmptyField } from './utils';
import { getEntityValidator } from '../schema/validator-register';
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
  initial: Record<string, unknown> | undefined
) => {
  if (!entitySetting) {
    return;
  }

  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (!attributesConfiguration) {
    return;
  }

  const mandatoryAttributes = attributesConfiguration.filter((attr) => attr.mandatory);
  const inputKeys = Object.keys(input);
  const initialKeys = initial !== undefined ? Object.keys(initial) : [];

  const inputValidValue = (mandatoryKey: string) => inputKeys.includes(mandatoryKey) && isNotEmptyField(input[mandatoryKey]);
  const initialValidValue = (mandatoryKey: string) => (initial !== undefined && initialKeys.includes(mandatoryKey) && isNotEmptyField(initial[mandatoryKey]));

  mandatoryAttributes.forEach((attr) => {
    if (!(inputValidValue(attr.name) || initialValidValue(attr.name))) {
      throw ValidationError(attr.name, { message: 'This attribute is mandatory', attribute: attr.name });
    }
  });
};

export const validateInput = async (
  context: AuthContext,
  user: AuthUser,
  instanceType: string,
  input: Record<string, unknown> | { key: string, value: string[] }[],
  entitySetting: BasicStoreEntityEntitySetting,
  initial?: Record<string, unknown>
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
  validateSchemaAttributes(instanceType, inputs);
  validateMandatoryAttributes(instanceType, inputs, entitySetting, initial);

  // Functional validator
  const validator = getEntityValidator(instanceType);

  if (validator) {
    const validate = await validator(context, user, inputs, initial?.id as string);
    if (!validate) {
      throw UnsupportedError('The input is not valid', { input: inputs });
    }
  }
};
