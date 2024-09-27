import * as R from 'ramda';
import Ajv from 'ajv';
import { schemaAttributesDefinition } from './schema-attributes';
import { UnsupportedError, ValidationError } from '../config/errors';
import type { AttributeConfiguration, BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from './validator-register';
import type { AuthContext, AuthUser } from '../types/user';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { externalReferences } from './stixRefRelationship';
import { telemetry } from '../config/tracing';
import type { AttributeDefinition } from './attribute-definition';
import type { EditInput } from '../generated/graphql';
import { EditOperation } from '../generated/graphql';
import { utcDate } from '../utils/format';
import { schemaRelationsRefDefinition } from './schema-relationsRef';
import { extendedErrors } from '../config/conf';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../utils/access';
import { TELEMETRY_DB_NAME, TELEMETRY_DB_OPERATION } from '../utils/telemetry-attributes';

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --
export const validateAndFormatSchemaAttribute = (
  attributeName: string,
  attributeDefinition: AttributeDefinition | undefined,
  editInput: EditInput
) => {
  // Basic validation
  if (!attributeDefinition || isEmptyField(editInput.value)) {
    return;
  }
  const isPatchObject = attributeDefinition.type === 'object' && !!editInput.object_path;
  if (!isPatchObject && !attributeDefinition.multiple && editInput.value.length > 1) {
    // with a patch object, the value matches something inside the object and not the object itself
    // so we cannot check directly the multiplicity as it concerns an internal mapping
    // let's assume it's OK, and validateDataBeforeIndexing would check it.
    throw ValidationError('Attribute cannot be multiple', attributeName, extendedErrors({ input: editInput }));
  }
  // Data validation
  if (attributeDefinition.type === 'string') {
    const values = [];
    for (let index = 0; index < editInput.value.length; index += 1) {
      const value = editInput.value[index];
      if (value && !R.is(String, value)) {
        throw ValidationError('Attribute must be a string', attributeName, extendedErrors({ input: editInput }));
      } else {
        values.push(value ? value.trim() : value);
      }
    }
    // This is reference change to trim the input and prevent unuseful stream events
    // TODO Find a better way to rework the data
    // eslint-disable-next-line no-param-reassign
    editInput.value = values;
    // Special validation for json
    if (attributeDefinition.format === 'json' && attributeDefinition.schemaDef) {
      const validate = ajv.compile(attributeDefinition.schemaDef);
      const jsonValue = R.head(editInput.value); // json cannot be multiple
      const valid = validate(JSON.parse(jsonValue as string));
      if (!valid) {
        throw ValidationError('The JSON schema is not valid', attributeName, { errors: validate.errors });
      }
    }
  }
  if (attributeDefinition.type === 'boolean') {
    editInput.value.forEach((value) => {
      if (value && !R.is(Boolean, value) && !R.is(String, value)) {
        throw ValidationError('Attribute must be a boolean/string', attributeName, extendedErrors({ input: editInput }));
      }
    });
  }
  if (attributeDefinition.type === 'date') {
    // Test date value (Accept only ISO date string)
    editInput.value.forEach((value) => {
      if (value && !R.is(String, value) && !utcDate(value).isValid()) {
        throw ValidationError('Attribute must be a boolean/string', attributeName, extendedErrors({ input: editInput }));
      }
    });
  }
  if (attributeDefinition.type === 'numeric') {
    // Test numeric value (Accept string)
    editInput.value.forEach((value) => {
      if (value && Number.isNaN(Number(value))) {
        throw ValidationError('Attribute must be a numeric/string', attributeName, extendedErrors({ input: editInput }));
      }
    });
  }
};

const validateFormatSchemaAttributes = async (context: AuthContext, user: AuthUser, instanceType: string, editInputs: EditInput[]) => {
  const validateFormatSchemaAttributesFn = async () => {
    const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);
    if (R.isEmpty(editInputs) || !Array.isArray(editInputs)) {
      throw UnsupportedError('Cannot validate an empty or invalid input', { ...extendedErrors({ input: editInputs }) });
    }
    editInputs.forEach((editInput) => {
      const attributeDefinition = availableAttributes.get(editInput.key);
      validateAndFormatSchemaAttribute(editInput.key, attributeDefinition, editInput);
    });
  };
  return telemetry(context, user, 'SCHEMA ATTRIBUTES VALIDATION', {
    [TELEMETRY_DB_NAME]: 'validation',
    [TELEMETRY_DB_OPERATION]: 'schema_attributes',
  }, validateFormatSchemaAttributesFn);
};

// -- VALIDATE ATTRIBUTE MANDATORY --

const validateMandatoryAttributes = (
  user: AuthUser,
  input: Record<string, unknown>,
  entitySetting: BasicStoreEntityEntitySetting,
  isCreation: boolean,
  validation: (inputKeys: string[], mandatoryKey: string) => boolean
) => {
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (!attributesConfiguration) {
    return;
  }
  let mandatoryAttributes: AttributeConfiguration[] = [];
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS)) {
    mandatoryAttributes = attributesConfiguration.filter((attr) => attr.mandatory);
  }
  // In creation if enforce reference is activated, user must provide a least 1 external references
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE) && isCreation && entitySetting.enforce_reference) {
    mandatoryAttributes.push({ name: externalReferences.name, mandatory: true });
  }
  const inputKeys = Object.keys(input);
  mandatoryAttributes.forEach((attr) => {
    if (!(validation(inputKeys, attr.name))) {
      throw ValidationError('This attribute is mandatory', attr.name);
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

    validateMandatoryAttributes(user, input, entitySetting, true, inputValidValue);
  };
  return telemetry(context, user, 'MANDATORY CREATION VALIDATION', {
    [TELEMETRY_DB_NAME]: 'validation',
    [TELEMETRY_DB_OPERATION]: 'mandatory',
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

    validateMandatoryAttributes(user, input, entitySetting, false, inputValidValue);
  };
  return telemetry(context, user, 'MANDATORY UPDATE VALIDATION', {
    [TELEMETRY_DB_NAME]: 'validation',
    [TELEMETRY_DB_OPERATION]: 'mandatory',
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
    await validateFormatSchemaAttributes(context, user, instanceType, editInputs);
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
    [TELEMETRY_DB_NAME]: 'validation',
    [TELEMETRY_DB_OPERATION]: 'creation',
  }, validateInputCreationFn);
};

export const validateUpdatableAttribute = (instanceType: string, input: Record<string, unknown>) => {
  const invalidKeys: string[] = [];
  Object.entries(input).forEach(([key]) => {
    const attribute = schemaAttributesDefinition.getAttribute(instanceType, key);
    const reference = schemaRelationsRefDefinition.getRelationRef(instanceType, key);
    const schemaAttribute = attribute || reference;
    if (!schemaAttribute || schemaAttribute.update === false) {
      invalidKeys.push(key);
    }
  });
  return invalidKeys;
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
    if (R.isEmpty(editInputs) || !Array.isArray(editInputs)) {
      throw UnsupportedError('Cannot validate an empty or invalid input', { input: editInputs });
    }
    // Convert input to record
    const instanceFromInputs: Record<string, unknown> = {};
    editInputs.forEach((obj) => { instanceFromInputs[obj.key] = obj.value; });
    // Generic validator
    await validateFormatSchemaAttributes(context, user, instanceType, editInputs);
    await validateMandatoryAttributesOnUpdate(context, user, instanceFromInputs, entitySetting);
    const errors = validateUpdatableAttribute(instanceType, instanceFromInputs);
    if (errors.length > 0) {
      throw ValidationError('You cannot update incompatible attribute', errors.at(0));
    }
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
    [TELEMETRY_DB_NAME]: 'validation',
    [TELEMETRY_DB_OPERATION]: 'update',
  }, validateInputUpdateFn);
};
