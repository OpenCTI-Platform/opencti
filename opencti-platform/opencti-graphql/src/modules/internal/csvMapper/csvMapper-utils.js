var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { isEmptyField, isNotEmptyField } from '../../../database/utils';
import { isStixRelationshipExceptRef } from '../../../schema/stixRelationship';
import { isStixObject } from '../../../schema/stixCoreObject';
import { CsvMapperRepresentationType } from './csvMapper-types';
import { fillDefaultValues, getEntitySettingFromCache } from '../../entitySetting/entitySetting-utils';
import { FunctionalError } from '../../../config/errors';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_REFS } from '../../../domain/attribute-utils';
import { internalFindByIds } from '../../../database/middleware-loader';
import { extractRepresentative } from '../../../database/entity-representative';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
const representationLabel = (idx, representation) => {
    const number = `#${idx + 1}`;
    if (isEmptyField(representation.target.entity_type)) {
        return `${number} New ${representation.type} representation`;
    }
    return `${number} ${representation.target.entity_type}`;
};
export const parseCsvMapper = (entity) => {
    return Object.assign(Object.assign({}, entity), { representations: typeof entity.representations === 'string' ? JSON.parse(entity.representations) : entity.representations });
};
export const parseCsvMapperWithDefaultValues = (context, user, entity) => __awaiter(void 0, void 0, void 0, function* () {
    if (typeof (entity === null || entity === void 0 ? void 0 : entity.representations) !== 'string') {
        return entity;
    }
    const parsedRepresentations = JSON.parse(entity.representations);
    const refAttributesIndexes = [];
    const refDefaultValues = parsedRepresentations.flatMap((representation, i) => {
        const refsDefinition = schemaRelationsRefDefinition
            .getRelationsRef(representation.target.entity_type)
            .filter((ref) => !INTERNAL_REFS.includes(ref.name));
        return representation.attributes.flatMap((attribute, j) => {
            if (attribute.default_values
                && attribute.key !== 'objectMarking'
                && refsDefinition.map((ref) => ref.name).includes(attribute.key)) {
                refAttributesIndexes.push(`${i}-${j}`);
                return attribute.default_values;
            }
            return [];
        });
    });
    const entities = yield internalFindByIds(context, user, refDefaultValues);
    return Object.assign(Object.assign({}, entity), { representations: parsedRepresentations.map((representation, i) => (Object.assign(Object.assign({}, representation), { attributes: representation.attributes.map((attribute, j) => {
                var _a;
                return (Object.assign(Object.assign({}, attribute), { default_values: (_a = attribute.default_values) === null || _a === void 0 ? void 0 : _a.map((val) => {
                        const refEntity = entities.find((e) => e.id === val);
                        const representative = refEntity ? extractRepresentative(refEntity).main : undefined;
                        return {
                            id: val,
                            name: refAttributesIndexes.includes(`${i}-${j}`) && representative
                                ? representative
                                : val
                        };
                    }) }));
            }) }))) });
});
export const isValidTargetType = (representation) => {
    if (representation.type === CsvMapperRepresentationType.relationship) {
        if (!isStixRelationshipExceptRef(representation.target.entity_type)) {
            throw FunctionalError('Unknown relationship', { type: representation.target.entity_type });
        }
    }
    else if (representation.type === CsvMapperRepresentationType.entity) {
        if (!isStixObject(representation.target.entity_type)) {
            throw FunctionalError('Unknown entity', { type: representation.target.entity_type });
        }
    }
};
export const validate = (context, user, mapper) => __awaiter(void 0, void 0, void 0, function* () {
    // consider empty csv mapper as invalid to avoid being used in the importer
    if (mapper.representations.length === 0) {
        throw Error(`CSV Mapper '${mapper.name}' has no representation`);
    }
    yield Promise.all(Array.from(mapper.representations.entries()).map(([idx, representation]) => __awaiter(void 0, void 0, void 0, function* () {
        // Validate target type
        isValidTargetType(representation);
        // Validate required attributes
        const entitySetting = yield getEntitySettingFromCache(context, representation.target.entity_type);
        const defaultValues = fillDefaultValues(user, {}, entitySetting);
        const attributesDefs = [
            ...schemaAttributesDefinition.getAttributes(representation.target.entity_type).values(),
        ].map((def) => ({
            name: def.name,
            mandatory: def.mandatoryType === 'external',
            multiple: def.multiple
        }));
        const refsDefs = [
            ...schemaRelationsRefDefinition.getRelationsRef(representation.target.entity_type),
        ].map((def) => ({
            name: def.name,
            mandatory: def.mandatoryType === 'external',
            multiple: def.multiple
        }));
        [...attributesDefs, ...refsDefs].filter((schemaAttribute) => schemaAttribute.mandatory)
            .forEach((schemaAttribute) => {
            var _a, _b;
            const attribute = representation.attributes.find((a) => schemaAttribute.name === a.key);
            const isColumnEmpty = isEmptyField((_a = attribute === null || attribute === void 0 ? void 0 : attribute.column) === null || _a === void 0 ? void 0 : _a.column_name) && isEmptyField((_b = attribute === null || attribute === void 0 ? void 0 : attribute.based_on) === null || _b === void 0 ? void 0 : _b.representations);
            const isDefaultValueEmpty = isEmptyField(defaultValues[schemaAttribute.name]);
            const isAttributeDefaultValueEmpty = isEmptyField(attribute === null || attribute === void 0 ? void 0 : attribute.default_values);
            if (isColumnEmpty && isDefaultValueEmpty && isAttributeDefaultValueEmpty) {
                throw FunctionalError('Missing values for required attribute', { representation: representationLabel(idx, representation), attribute: schemaAttribute.name });
            }
        });
        // Validate representation attribute configuration
        representation.attributes.forEach((attribute) => {
            var _a, _b, _c, _d, _e, _f;
            // Validate based on configuration
            if (isNotEmptyField((_a = attribute.based_on) === null || _a === void 0 ? void 0 : _a.representations)) {
                const schemaAttribute = [...attributesDefs, ...refsDefs].find((attr) => attr.name === attribute.key);
                // Multiple
                if (!(schemaAttribute === null || schemaAttribute === void 0 ? void 0 : schemaAttribute.multiple) && ((_d = (_c = (_b = attribute.based_on) === null || _b === void 0 ? void 0 : _b.representations) === null || _c === void 0 ? void 0 : _c.length) !== null && _d !== void 0 ? _d : 0) > 1) {
                    throw FunctionalError('Attribute can\'t be multiple', { representation: representationLabel(idx, representation), attribute: attribute.key });
                }
                // Auto reference
                if ((_f = (_e = attribute.based_on) === null || _e === void 0 ? void 0 : _e.representations) === null || _f === void 0 ? void 0 : _f.includes(representation.id)) {
                    throw FunctionalError('Can\'t reference the representation itself', { representation: representationLabel(idx, representation), attribute: attribute.key });
                }
                // Possible cycle
                const representationRefs = mapper.representations.filter((r) => { var _a, _b; return (_b = (_a = attribute.based_on) === null || _a === void 0 ? void 0 : _a.representations) === null || _b === void 0 ? void 0 : _b.includes(r.id); });
                const attributeRepresentationRefs = representationRefs.map((rr) => rr.attributes
                    .filter((rra) => { var _a; return isNotEmptyField((_a = rra.based_on) === null || _a === void 0 ? void 0 : _a.representations); })
                    .map((rra) => { var _a, _b; return (_b = (_a = rra.based_on) === null || _a === void 0 ? void 0 : _a.representations) !== null && _b !== void 0 ? _b : []; })
                    .flat())
                    .flat();
                if (attributeRepresentationRefs.includes(representation.id)) {
                    throw FunctionalError('Reference cycle found', { representation: representationLabel(idx, representation) });
                }
            }
        });
    })));
});
export const errors = (context, user, csvMapper) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        yield validate(context, user, parseCsvMapper(csvMapper));
        return null;
    }
    catch (error) {
        if (error instanceof Error) {
            return error.message;
        }
        return 'Unknown error';
    }
});
export const sanitized = (mapper) => {
    return Object.assign(Object.assign({}, mapper), { representations: mapper.representations.map((r) => {
            return Object.assign(Object.assign({}, r), { attributes: r.attributes.filter((attr) => {
                    var _a, _b;
                    return (isNotEmptyField((_a = attr.based_on) === null || _a === void 0 ? void 0 : _a.representations)
                        || isNotEmptyField((_b = attr.column) === null || _b === void 0 ? void 0 : _b.column_name)
                        || isNotEmptyField(attr.default_values));
                }) });
        }) });
};
