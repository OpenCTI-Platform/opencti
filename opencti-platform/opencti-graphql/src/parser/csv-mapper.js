var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* eslint-disable no-param-reassign */
import moment from 'moment';
import { entityType, relationshipType, standardId } from '../schema/attribute-definition';
import { generateStandardId } from '../schema/identifier';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { handleInnerType } from '../domain/stixDomainObject';
import { extractValueFromCsv } from './csv-helper';
import { isStixRelationshipExceptRef } from '../schema/stixRelationship';
import { CsvMapperRepresentationType, Operator } from '../modules/internal/csvMapper/csvMapper-types';
import { isValidTargetType } from '../modules/internal/csvMapper/csvMapper-utils';
import { fillDefaultValues, getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { UnsupportedError } from '../config/errors';
import { internalFindByIdsMapped } from '../database/middleware-loader';
import { INPUT_MARKINGS } from '../schema/general';
// -- HANDLE VALUE --
const formatValue = (value, type, column) => {
    var _a, _b;
    const pattern_date = (_a = column === null || column === void 0 ? void 0 : column.configuration) === null || _a === void 0 ? void 0 : _a.pattern_date;
    const timezone = (_b = column === null || column === void 0 ? void 0 : column.configuration) === null || _b === void 0 ? void 0 : _b.timezone;
    if (type === 'string') {
        return value.trim();
    }
    if (type === 'numeric') {
        const formattedValue = Number(value);
        return Number.isNaN(formattedValue) ? null : formattedValue;
    }
    if (type === 'date') {
        try {
            moment.suppressDeprecationWarnings = true;
            if (isNotEmptyField(pattern_date)) {
                if (isNotEmptyField(timezone)) {
                    return moment(value, pattern_date, timezone).toISOString();
                }
                return moment(value, pattern_date).toISOString();
            }
            return moment(value).toISOString();
        }
        catch (error) {
            return null;
        }
    }
    if (type === 'boolean') {
        const stringBoolean = value.toLowerCase().trim();
        // TODO Matching value must be configurable in parser option
        return stringBoolean === 'true' || stringBoolean === 'yes' || stringBoolean === '1';
    }
    return value;
};
const computeValue = (value, column, attributeDef) => {
    var _a;
    if (value === undefined || isEmptyField(value)) {
        return null;
    }
    // Handle multiple
    if (attributeDef.multiple) {
        if ((_a = column.configuration) === null || _a === void 0 ? void 0 : _a.separator) {
            return value.split(column.configuration.separator).map((v) => formatValue(v, attributeDef.type, column));
        }
        return [formatValue(value, attributeDef.type, column)];
    }
    // Handle single
    return formatValue(value, attributeDef.type, column);
};
const computeDefaultValue = (defaultValue, attribute, definition) => {
    // Handle multiple
    if (definition.multiple) {
        return defaultValue.map((v) => formatValue(v, definition.type, attribute.column));
    }
    // Handle single
    return formatValue(defaultValue[0], definition.type, attribute.column);
};
// -- VALIDATION --
const isValidTarget = (record, representation) => {
    // Target type
    isValidTargetType(representation);
    // Column based
    const columnBased = representation.target.column_based;
    if (columnBased) {
        const recordValue = extractValueFromCsv(record, columnBased.column_reference);
        if (columnBased.operator === Operator.eq) {
            return recordValue === columnBased.value;
        }
        if (columnBased.operator === Operator.neq) {
            return recordValue !== columnBased.value;
        }
        return false;
    }
    return true;
};
const isValidInput = (input) => {
    // Verify from and to are filled for relationship
    if (isStixRelationshipExceptRef(input[entityType.name])) {
        if (isEmptyField(input.from) || isEmptyField(input.to)) {
            return false;
        }
    }
    // Verify mandatory attributes are filled
    // TODO: Removed it when it will be handle in schema-validator
    const mandatoryAttributes = Array.from(schemaAttributesDefinition.getAttributes(input[entityType.name]).values())
        .filter((attr) => attr.mandatoryType === 'external')
        .map((attr) => attr.name);
    const mandatoryRefs = schemaRelationsRefDefinition.getRelationsRef(input[entityType.name])
        .filter((ref) => ref.mandatoryType === 'external')
        .map((ref) => ref.name);
    return [...mandatoryAttributes, ...mandatoryRefs].every((key) => isNotEmptyField(input[key]));
};
// -- COMPUTE --
const handleType = (representation, input) => {
    const { entity_type } = representation.target;
    input[entityType.name] = entity_type;
    if (representation.type === CsvMapperRepresentationType.relationship) {
        input[relationshipType.name] = entity_type;
    }
};
const handleId = (representation, input) => {
    input[standardId.name] = generateStandardId(representation.target.entity_type, input);
};
const handleDirectAttribute = (attribute, input, record, definition) => {
    var _a;
    if (attribute.default_values !== null && attribute.default_values !== undefined) {
        const computedDefault = computeDefaultValue(attribute.default_values, attribute, definition);
        if (computedDefault !== null && computedDefault !== undefined) {
            input[attribute.key] = computedDefault;
        }
    }
    if (attribute.column && isNotEmptyField((_a = attribute.column) === null || _a === void 0 ? void 0 : _a.column_name)) {
        const recordValue = extractValueFromCsv(record, attribute.column.column_name);
        const computedValue = computeValue(recordValue, attribute.column, definition);
        if (computedValue !== null && computedValue !== undefined) {
            input[attribute.key] = computedValue;
        }
    }
};
const handleBasedOnAttribute = (attribute, input, definition, otherEntities, refEntities) => {
    var _a;
    // Handle default value based_on attribute except markings which are handled later on.
    if (definition && attribute.default_values && attribute.default_values.length > 0 && attribute.key !== INPUT_MARKINGS) {
        if (definition.multiple) {
            input[attribute.key] = attribute.default_values.flatMap((id) => {
                const entity = refEntities[id];
                if (!entity)
                    return [];
                return [entity];
            });
        }
        else {
            const entity = refEntities[attribute.default_values[0]];
            if (entity) {
                input[attribute.key] = entity;
            }
        }
    }
    if (attribute.based_on) {
        if (isEmptyField(attribute.based_on)) {
            throw UnsupportedError('Unknown value(s)', { key: attribute.key });
        }
        const entities = ((_a = attribute.based_on.representations) !== null && _a !== void 0 ? _a : [])
            .map((id) => otherEntities.get(id))
            .filter((e) => e !== undefined);
        if (entities.length > 0) {
            const entity_type = input[entityType.name];
            // Is relation from or to (stix-core || stix-sighting)
            if (isStixRelationshipExceptRef(entity_type) && ['from', 'to'].includes(attribute.key)) {
                if (attribute.key === 'from') {
                    const entity = entities[0];
                    if (isNotEmptyField(entity)) {
                        input.from = entity;
                        input.fromType = entity[entityType.name];
                    }
                }
                else if (attribute.key === 'to') {
                    const entity = entities[0];
                    if (isNotEmptyField(entity)) {
                        input.to = entity;
                        input.toType = entity[entityType.name];
                    }
                }
                // Is relation ref
            }
            else if (definition) {
                const refs = definition.multiple ? entities : entities[0];
                if (isNotEmptyField(refs)) {
                    input[attribute.key] = refs;
                }
            }
        }
    }
};
const handleAttributes = (record, representation, input, otherEntities, refEntities) => {
    var _a;
    const { entity_type } = representation.target;
    ((_a = representation.attributes) !== null && _a !== void 0 ? _a : []).forEach((attribute) => {
        const attributeDef = schemaAttributesDefinition.getAttribute(entity_type, attribute.key);
        const refDef = schemaRelationsRefDefinition.getRelationRef(entity_type, attribute.key);
        if (attributeDef) {
            // Handle column attribute
            handleDirectAttribute(attribute, input, record, attributeDef);
        }
        else if (refDef || ['from', 'to'].includes(attribute.key)) {
            handleBasedOnAttribute(attribute, input, refDef, otherEntities, refEntities);
        }
        else {
            throw UnsupportedError('Unknown schema for attribute:', { attribute });
        }
    });
};
/**
 * We handle markings in a specific function instead of doing it inside the
 * handleAttributes() one because we need to do specific logic for this attribute.
 */
const handleDefaultMarkings = (entitySetting, representation, input, refEntities, chosenMarkings, user) => {
    var _a, _b, _c, _d, _e, _f, _g;
    if (input[INPUT_MARKINGS]) {
        return;
    }
    // Find default markings policy in entity settings ("true" or undefined).
    const settingAttributes = entitySetting ? getAttributesConfiguration(entitySetting) : undefined;
    const settingMarkingValue = (_b = (_a = settingAttributes === null || settingAttributes === void 0 ? void 0 : settingAttributes.find((attribute) => attribute.name === INPUT_MARKINGS)) === null || _a === void 0 ? void 0 : _a.default_values) === null || _b === void 0 ? void 0 : _b[0];
    // Find default markings policy in mapper representation ("user-default" or "user-choice"  or undefined).
    const representationMarkingValue = (_d = (_c = representation.attributes
        .find((attribute) => attribute.key === INPUT_MARKINGS)) === null || _c === void 0 ? void 0 : _c.default_values) === null || _d === void 0 ? void 0 : _d[0];
    // Retrieve default markings of the user.
    const userDefaultMarkings = (_g = (_f = ((_e = user.default_marking) !== null && _e !== void 0 ? _e : [])
        .find((entry) => entry.entity_type === 'GLOBAL')) === null || _f === void 0 ? void 0 : _f.values) !== null && _g !== void 0 ? _g : [];
    if (representationMarkingValue) {
        if (representationMarkingValue === 'user-choice') {
            input[INPUT_MARKINGS] = chosenMarkings.flatMap((id) => {
                const entity = refEntities[id];
                if (!entity)
                    return [];
                return [entity];
            });
        }
        else {
            input[INPUT_MARKINGS] = userDefaultMarkings;
        }
    }
    else if (settingMarkingValue) {
        input[INPUT_MARKINGS] = userDefaultMarkings;
    }
};
const mapRecord = (context, user, record, representation, otherEntities, refEntities, chosenMarkings) => __awaiter(void 0, void 0, void 0, function* () {
    if (!isValidTarget(record, representation)) {
        return null;
    }
    const { entity_type } = representation.target;
    let input = {};
    handleType(representation, input);
    input = handleInnerType(input, entity_type);
    handleAttributes(record, representation, input, otherEntities, refEntities);
    const entitySetting = yield getEntitySettingFromCache(context, entity_type);
    handleDefaultMarkings(entitySetting, representation, input, refEntities, chosenMarkings, user);
    const filledInput = fillDefaultValues(user, input, entitySetting);
    if (!isValidInput(filledInput)) {
        return null;
    }
    handleId(representation, filledInput);
    return filledInput;
});
export const mappingProcess = (context, user, mapper, record) => __awaiter(void 0, void 0, void 0, function* () {
    const { representations, user_chosen_markings } = mapper;
    // IDs of entity refs retrieved from default values of based_on attributes in csv mapper.
    const refIdsToResolve = new Set(representations.flatMap((representation) => {
        const { target } = representation;
        return representation.attributes.flatMap((attribute) => {
            if (attribute.default_values && attribute.default_values.length > 0) {
                const refDef = schemaRelationsRefDefinition.getRelationRef(target.entity_type, attribute.key);
                if (refDef) {
                    return attribute.default_values;
                }
            }
            return [];
        });
    }));
    const refEntities = yield internalFindByIdsMapped(context, user, [
        ...refIdsToResolve,
        // Also resolve the markings chosen by the user if any.
        ...(user_chosen_markings || []),
    ]);
    const representationEntities = representations
        .filter((r) => r.type === CsvMapperRepresentationType.entity)
        .sort((r1, r2) => r1.attributes.filter((attr) => attr.based_on).length - r2.attributes.filter((attr) => attr.based_on).length);
    const representationRelationships = representations.filter((r) => r.type === CsvMapperRepresentationType.relationship);
    const results = new Map();
    // 1. entities sort by no based on at first
    for (let i = 0; i < representationEntities.length; i += 1) {
        const representation = representationEntities[i];
        const input = yield mapRecord(context, user, record, representation, results, refEntities, user_chosen_markings !== null && user_chosen_markings !== void 0 ? user_chosen_markings : []);
        if (input) {
            results.set(representation.id, input);
        }
    }
    // 2. relationships
    for (let i = 0; i < representationRelationships.length; i += 1) {
        const representation = representationRelationships[i];
        const input = yield mapRecord(context, user, record, representation, results, refEntities, user_chosen_markings !== null && user_chosen_markings !== void 0 ? user_chosen_markings : []);
        if (input) {
            results.set(representation.id, input);
        }
    }
    return Array.from(results.values());
});
