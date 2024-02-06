var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as R from 'ramda';
import Ajv from 'ajv';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { schemaAttributesDefinition } from './schema-attributes';
import { UnsupportedError, ValidationError } from '../config/errors';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from './validator-register';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { externalReferences } from './stixRefRelationship';
import { telemetry } from '../config/tracing';
import { EditOperation } from '../generated/graphql';
import { utcDate } from '../utils/format';
const ajv = new Ajv();
// -- VALIDATE ATTRIBUTE AVAILABILITY AND FORMAT --
export const validateAndFormatSchemaAttribute = (attributeName, attributeDefinition, editInput) => {
    // Basic validation
    if (!attributeDefinition || isEmptyField(editInput.value)) {
        return;
    }
    if (!attributeDefinition.multiple && editInput.value.length > 1) {
        throw ValidationError(attributeName, { message: `Attribute ${attributeName} cannot be multiple`, data: editInput });
    }
    // Data validation
    if (attributeDefinition.type === 'string') {
        const values = [];
        for (let index = 0; index < editInput.value.length; index += 1) {
            const value = editInput.value[index];
            if (value && !R.is(String, value)) {
                throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a string`, data: editInput });
            }
            else {
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
            const valid = validate(JSON.parse(jsonValue));
            if (!valid) {
                throw ValidationError(attributeName, { message: 'The JSON schema is not valid', data: validate.errors });
            }
        }
    }
    if (attributeDefinition.type === 'boolean') {
        editInput.value.forEach((value) => {
            if (value && !R.is(Boolean, value) && !R.is(String, value)) {
                throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a boolean/string`, data: editInput });
            }
        });
    }
    if (attributeDefinition.type === 'date') {
        // Test date value (Accept only ISO date string)
        editInput.value.forEach((value) => {
            if (value && !R.is(String, value) && !utcDate(value).isValid()) {
                throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a boolean/string`, data: editInput });
            }
        });
    }
    if (attributeDefinition.type === 'numeric') {
        // Test numeric value (Accept string)
        editInput.value.forEach((value) => {
            if (value && Number.isNaN(Number(value))) {
                throw ValidationError(attributeName, { message: `Attribute ${attributeName} must be a numeric/string`, data: editInput });
            }
        });
    }
    if (attributeDefinition.type === 'object') {
        // TODO JRI Implements a checker
    }
};
const validateFormatSchemaAttributes = (context, user, instanceType, editInputs) => __awaiter(void 0, void 0, void 0, function* () {
    const validateFormatSchemaAttributesFn = () => __awaiter(void 0, void 0, void 0, function* () {
        const availableAttributes = schemaAttributesDefinition.getAttributes(instanceType);
        editInputs.forEach((editInput) => {
            const attributeDefinition = availableAttributes.get(editInput.key);
            validateAndFormatSchemaAttribute(editInput.key, attributeDefinition, editInput);
        });
    });
    return telemetry(context, user, 'SCHEMA ATTRIBUTES VALIDATION', {
        [SemanticAttributes.DB_NAME]: 'validation',
        [SemanticAttributes.DB_OPERATION]: 'schema_attributes',
    }, validateFormatSchemaAttributesFn);
});
// -- VALIDATE ATTRIBUTE MANDATORY --
const validateMandatoryAttributes = (input, entitySetting, isCreation, validation) => {
    const attributesConfiguration = getAttributesConfiguration(entitySetting);
    if (!attributesConfiguration) {
        return;
    }
    const mandatoryAttributes = attributesConfiguration.filter((attr) => attr.mandatory);
    // In creation if enforce reference is activated, user must provide a least 1 external references
    if (isCreation && entitySetting.enforce_reference) {
        mandatoryAttributes.push({ name: externalReferences.name, mandatory: true });
    }
    const inputKeys = Object.keys(input);
    mandatoryAttributes.forEach((attr) => {
        if (!(validation(inputKeys, attr.name))) {
            throw ValidationError(attr.name, { message: 'This attribute is mandatory', attribute: attr.name });
        }
    });
};
const validateMandatoryAttributesOnCreation = (context, user, input, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const validateMandatoryAttributesOnCreationFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // Should have all the mandatory keys and the associated values not null
        const inputValidValue = (inputKeys, mandatoryKey) => (inputKeys.includes(mandatoryKey)
            && (Array.isArray(input[mandatoryKey]) ? input[mandatoryKey].some((i) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));
        validateMandatoryAttributes(input, entitySetting, true, inputValidValue);
    });
    return telemetry(context, user, 'MANDATORY CREATION VALIDATION', {
        [SemanticAttributes.DB_NAME]: 'validation',
        [SemanticAttributes.DB_OPERATION]: 'mandatory',
    }, validateMandatoryAttributesOnCreationFn);
});
const validateMandatoryAttributesOnUpdate = (context, user, input, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const validateMandatoryAttributesOnUpdateFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // If the mandatory key is present the associated value should be not null
        const inputValidValue = (inputKeys, mandatoryKey) => (!inputKeys.includes(mandatoryKey)
            || (Array.isArray(input[mandatoryKey]) ? input[mandatoryKey].some((i) => isNotEmptyField(i)) : isNotEmptyField(input[mandatoryKey])));
        validateMandatoryAttributes(input, entitySetting, false, inputValidValue);
    });
    return telemetry(context, user, 'MANDATORY UPDATE VALIDATION', {
        [SemanticAttributes.DB_NAME]: 'validation',
        [SemanticAttributes.DB_OPERATION]: 'mandatory',
    }, validateMandatoryAttributesOnUpdateFn);
});
export const validateInputCreation = (context, user, instanceType, input, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const validateInputCreationFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // Generic validator
        const editInputs = Object.entries(input)
            .map(([k, v]) => ({ operation: EditOperation.Replace, value: Array.isArray(v) ? v : [v], key: k }));
        yield validateFormatSchemaAttributes(context, user, instanceType, editInputs);
        yield validateMandatoryAttributesOnCreation(context, user, input, entitySetting);
        // Functional validator
        const validator = getEntityValidatorCreation(instanceType);
        if (validator) {
            const validate = yield validator(context, user, input);
            if (!validate) {
                throw UnsupportedError('The input is not valid', { input });
            }
        }
    });
    return telemetry(context, user, 'CREATION VALIDATION', {
        [SemanticAttributes.DB_NAME]: 'validation',
        [SemanticAttributes.DB_OPERATION]: 'creation',
    }, validateInputCreationFn);
});
const validateUpdatableAttribute = (instanceType, input) => {
    Object.entries(input).forEach(([key]) => {
        const attribute = schemaAttributesDefinition.getAttribute(instanceType, key);
        if ((attribute === null || attribute === void 0 ? void 0 : attribute.update) === false) {
            throw ValidationError(attribute.name, { message: `You cannot update ${attribute.name} attribute` });
        }
    });
};
export const validateInputUpdate = (context, user, instanceType, initial, editInputs, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const validateInputUpdateFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // Convert input to record
        const instanceFromInputs = {};
        editInputs.forEach((obj) => { instanceFromInputs[obj.key] = obj.value; });
        // Generic validator
        yield validateFormatSchemaAttributes(context, user, instanceType, editInputs);
        yield validateMandatoryAttributesOnUpdate(context, user, instanceFromInputs, entitySetting);
        validateUpdatableAttribute(instanceType, instanceFromInputs);
        // Functional validator
        const validator = getEntityValidatorUpdate(instanceType);
        if (validator) {
            const validate = yield validator(context, user, instanceFromInputs, initial);
            if (!validate) {
                throw UnsupportedError('The input is not valid', { inputs: instanceFromInputs });
            }
        }
    });
    return telemetry(context, user, 'UPDATE VALIDATION', {
        [SemanticAttributes.DB_NAME]: 'validation',
        [SemanticAttributes.DB_OPERATION]: 'update',
    }, validateInputUpdateFn);
});
