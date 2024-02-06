var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { internalFindByIdsMapped, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_CSV_MAPPER } from './csvMapper-types';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../../domain/internalObject';
import { bundleProcess } from '../../../parser/csv-bundler';
import { parseCsvMapperWithDefaultValues } from './csvMapper-utils';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_ATTRIBUTES, INTERNAL_REFS } from '../../../domain/attribute-utils';
import { getEntitiesListFromCache } from '../../../database/cache';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../entitySetting/entitySetting-types';
import { SYSTEM_USER } from '../../../utils/access';
import { getAttributesConfiguration } from '../../entitySetting/entitySetting-utils';
import { isNotEmptyField } from '../../../database/utils';
import { extractRepresentative } from '../../../database/entity-representative';
import { isStixCoreRelationship } from '../../../schema/stixCoreRelationship';
// -- UTILS --
export const csvMapperTest = (context, user, configuration, content) => __awaiter(void 0, void 0, void 0, function* () {
    const limitedTestingText = content.split(/\r?\n/).slice(0, 100).join('\n'); // Get 100 lines max
    const csvMapper = yield parseCsvMapperWithDefaultValues(context, user, JSON.parse(configuration));
    const bundle = yield bundleProcess(context, user, Buffer.from(limitedTestingText), csvMapper);
    return {
        objects: JSON.stringify(bundle.objects, null, 2),
        nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
        nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
    };
});
// -- CRUD --
export const findById = (context, user, csvMapperId) => __awaiter(void 0, void 0, void 0, function* () {
    const csvMapper = yield storeLoadById(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
    return parseCsvMapperWithDefaultValues(context, user, csvMapper);
});
export const findAll = (context, user, opts) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_CSV_MAPPER], opts);
};
export const createCsvMapper = (context, user, csvMapperInput) => __awaiter(void 0, void 0, void 0, function* () {
    return createInternalObject(context, user, csvMapperInput, ENTITY_TYPE_CSV_MAPPER)
        .then((entity) => parseCsvMapperWithDefaultValues(context, user, entity));
});
export const fieldPatchCsvMapper = (context, user, csvMapperId, input) => __awaiter(void 0, void 0, void 0, function* () {
    return editInternalObject(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER, input)
        .then((entity) => parseCsvMapperWithDefaultValues(context, user, entity));
});
export const deleteCsvMapper = (context, user, csvMapperId) => __awaiter(void 0, void 0, void 0, function* () {
    return deleteInternalObject(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
});
// -- Schema
// Fetch the list of schemas attributes by entity type extended with
// what is saved in entity settings if any.
export const csvMapperSchemaAttributes = (context, user) => __awaiter(void 0, void 0, void 0, function* () {
    const schemaAttributes = [];
    // Add attribute definitions
    const attributesDefinitions = schemaAttributesDefinition.attributes;
    Object.keys(attributesDefinitions).forEach((key) => {
        const attributesDef = schemaAttributesDefinition.getAttributes(key);
        const attributes = Array.from(attributesDef.values()).flatMap((attribute) => {
            if (INTERNAL_ATTRIBUTES.includes(attribute.name))
                return [];
            return [{
                    name: attribute.name,
                    label: attribute.label,
                    type: attribute.type,
                    mandatoryType: attribute.mandatoryType,
                    mandatory: attribute.mandatoryType === 'external',
                    editDefault: attribute.editDefault,
                    multiple: attribute.multiple,
                }];
        });
        if (isStixCoreRelationship(key)) {
            attributes.push({
                name: 'from',
                label: 'from',
                type: 'ref',
                mandatoryType: 'external',
                multiple: false,
                mandatory: true,
                editDefault: false
            });
            attributes.push({
                name: 'to',
                label: 'to',
                type: 'ref',
                mandatoryType: 'external',
                multiple: false,
                mandatory: true,
                editDefault: false
            });
        }
        schemaAttributes.push({
            name: key,
            attributes
        });
    });
    // Add refs definitions
    const refsNames = schemaRelationsRefDefinition.getAllInputNames();
    const refsDefinitions = schemaRelationsRefDefinition.relationsRef;
    Object.keys(refsDefinitions).forEach((key) => {
        var _a;
        const refs = schemaRelationsRefDefinition.getRelationsRef(key);
        const schemaAttribute = (_a = schemaAttributes.find((a) => a.name === key)) !== null && _a !== void 0 ? _a : {
            name: key,
            attributes: []
        };
        schemaAttribute.attributes.push(...Array.from(refs.values()).flatMap((ref) => {
            if (INTERNAL_REFS.includes(ref.name))
                return [];
            return [{
                    name: ref.name,
                    label: ref.label,
                    type: 'ref',
                    mandatoryType: ref.mandatoryType,
                    mandatory: ref.mandatoryType === 'external',
                    editDefault: ref.editDefault,
                    multiple: ref.multiple,
                }];
        }));
    });
    // Used to resolve later default values ref with ids.
    const attributesDefaultValuesToResolve = {};
    // Extend schema attributes with entity settings if any
    const entitySettings = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
    entitySettings.forEach((entitySetting) => {
        var _a;
        const schemaIndex = schemaAttributes.findIndex((s) => s.name === entitySetting.target_type);
        if (schemaIndex > -1) {
            const schemaAttribute = schemaAttributes[schemaIndex];
            (_a = getAttributesConfiguration(entitySetting)) === null || _a === void 0 ? void 0 : _a.forEach((userDefinedAttr) => {
                var _a, _b;
                const attributeIndex = schemaAttribute.attributes.findIndex((a) => a.name === userDefinedAttr.name);
                if (attributeIndex > -1) {
                    const attribute = schemaAttribute.attributes[attributeIndex];
                    if (attribute.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
                        attribute.mandatory = userDefinedAttr.mandatory;
                    }
                    if (isNotEmptyField(userDefinedAttr.default_values)) {
                        attribute.defaultValues = (_a = userDefinedAttr.default_values) === null || _a === void 0 ? void 0 : _a.map((v) => ({ id: v, name: v }));
                        // If the default value is a ref with an id, save it to resolve it below.
                        if (attribute.name !== 'objectMarking' && refsNames.includes(attribute.name)) {
                            attributesDefaultValuesToResolve[`${schemaIndex}-${attributeIndex}`] = (_b = userDefinedAttr.default_values) !== null && _b !== void 0 ? _b : [];
                        }
                    }
                }
            });
        }
    });
    // Resolve default values ref ids
    const idsToResolve = Object.values(attributesDefaultValuesToResolve).flat();
    const entities = yield internalFindByIdsMapped(context, user, idsToResolve);
    Object.keys(attributesDefaultValuesToResolve).forEach((indexes) => {
        var _a, _b;
        const [schemaIndex, attributeIndex] = indexes.split('-').map(Number);
        const defaultValues = (_b = (_a = schemaAttributes[schemaIndex]) === null || _a === void 0 ? void 0 : _a.attributes[attributeIndex]) === null || _b === void 0 ? void 0 : _b.defaultValues;
        if (defaultValues) {
            schemaAttributes[schemaIndex].attributes[attributeIndex].defaultValues = defaultValues.map((val) => {
                var _a;
                const entity = entities[val.id];
                return {
                    id: val.id,
                    name: entity ? ((_a = extractRepresentative(entity).main) !== null && _a !== void 0 ? _a : val.id) : val.id
                };
            });
        }
    });
    return schemaAttributes;
});
