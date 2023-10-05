import * as R from 'ramda';
import Ajv from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { JSONPath } from 'jsonpath-plus';
import { isJsonAttribute, isObjectAttribute, schemaAttributesDefinition } from './schema-attributes';
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

const ajv = new Ajv();

// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --

export const extractSchemaDefFromPath = (attributeDefinition: AttributeDefinition, pointer: string, editInput: EditInput): object | object[] => {
  const configPath = pointer.split('/').filter((a) => isNotEmptyField(a) && a !== editInput.key)
    .map((t) => (!Number.isNaN(Number(t)) ? 'items' : (`properties.${t}`))).join('.');
  const configSchema = JSONPath({ json: attributeDefinition.schemaDef as object, resultType: 'value', wrap: false, path: configPath });
  return configSchema?.type === undefined || configSchema?.type === 'array' ? editInput.value : R.head(editInput.value);
};

export const validateFormatSchemaAttribute = (
  instanceType: string,
  attributeName: string,
  attributeDefinition: AttributeDefinition | undefined,
  initial: object,
  editInput: EditInput
) => {
  if (isJsonAttribute(attributeName) || isObjectAttribute(attributeName)) {
    if (!attributeDefinition) {
      throw ValidationError(attributeName, {
        message: 'This attribute is not declared for this type',
        data: { attribute: attributeName, entityType: instanceType }
      });
    }
    if (attributeDefinition.schemaDef) {
      const validate = ajv.compile(attributeDefinition.schemaDef);
      if (isJsonAttribute(attributeName)) {
        const jsonValue = R.head(editInput.value); // json cannot be multiple
        const valid = validate(JSON.parse(jsonValue as string));
        if (!valid) {
          throw ValidationError(attributeName, { message: 'The JSON schema is not valid', data: validate.errors });
        }
      }
      if (isObjectAttribute(attributeName)) {
        let validationValues = editInput.value;
        if (editInput.object_path) {
          // If object path is setup, controlling the field is much harder.
          // Concept here is to apply the partial operation and check if the result comply to the schema
          const pointers = JSONPath({ json: initial, resultType: 'pointer', path: `${editInput.key}${editInput.object_path}` });
          const patch = pointers.map((p: string) => ({ op: editInput.operation, path: p, value: extractSchemaDefFromPath(attributeDefinition, p, editInput) }));
          const patchedInstance = jsonpatch.applyPatch(R.clone(initial), patch).newDocument as any;
          validationValues = patchedInstance[editInput.key];
        }
        const valid = validate(validationValues);
        if (!valid) {
          throw ValidationError(attributeName, { message: 'The Object schema is not valid', data: validate.errors });
        }
      }
    }
  }
};

const validateFormatSchemaAttributes = async (context: AuthContext, user: AuthUser, instanceType: string, initial: Record<string, unknown>, editInputs: EditInput[]) => {
  const validateFormatSchemaAttributesFn = async () => {
    const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);
    editInputs.forEach((editInput) => {
      const attributeDefinition = availableAttributes.get(editInput.key);
      validateFormatSchemaAttribute(instanceType, editInput.key, attributeDefinition, initial, editInput);
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
