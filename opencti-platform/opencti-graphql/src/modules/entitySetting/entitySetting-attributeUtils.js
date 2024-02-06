var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { defaultScale, getAttributesConfiguration } from './entitySetting-utils';
import { telemetry } from '../../config/tracing';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { isNotEmptyField } from '../../database/utils';
import { internalFindByIdsMapped } from '../../database/middleware-loader';
import { extractRepresentative } from '../../database/entity-representative';
// ==================================================================
// Need a specific utils file to those functions because
// getMandatoryAttributesForSetting() is called inside middleware.js,
// and so we have a cycle dependency if writing it inside .-domain.ts
// ==================================================================
// Fetch the schemas attributes for an entity setting and extend them with
// what is saved in this entity setting.
export const getEntitySettingSchemaAttributes = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    return telemetry(context, user, 'ATTRIBUTES', {
        [SemanticAttributes.DB_NAME]: 'attributes_domain',
        [SemanticAttributes.DB_OPERATION]: 'attributes_definition',
    }, () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        if (!entitySetting) {
            return [];
        }
        const { target_type } = entitySetting;
        const attributesDefinition = schemaAttributesDefinition.getAttributes(target_type);
        const refsDefinition = schemaRelationsRefDefinition.getRelationsRef(target_type);
        const refsNames = schemaRelationsRefDefinition.getInputNames(target_type);
        const schemaAttributes = [
            // Configs for attributes definition
            ...Array.from(attributesDefinition.values())
                .filter((attr) => (attr.editDefault
                || attr.mandatoryType === 'external'
                || attr.mandatoryType === 'customizable'))
                .map((attr) => ({
                name: attr.name,
                label: attr.label,
                type: attr.type,
                mandatoryType: attr.mandatoryType,
                editDefault: attr.editDefault,
                multiple: attr.multiple,
                mandatory: attr.mandatoryType === 'external',
                scale: (attr.type === 'numeric' && attr.scalable) ? defaultScale : undefined
            })),
            // Configs for refs definition
            ...Array.from(refsDefinition.values())
                .filter((ref) => (ref.mandatoryType === 'external'
                || ref.mandatoryType === 'customizable'))
                .map((ref) => ({
                name: ref.name,
                label: ref.label,
                editDefault: ref.editDefault,
                type: 'ref',
                mandatoryType: ref.mandatoryType,
                multiple: ref.multiple,
                mandatory: ref.mandatoryType === 'external',
            })),
        ];
        // Used to resolve later default values ref with ids.
        const attributesDefaultValuesToResolve = {};
        // Extend schema attributes with entity settings data.
        (_a = getAttributesConfiguration(entitySetting)) === null || _a === void 0 ? void 0 : _a.forEach((userDefinedAttr) => {
            var _a, _b;
            const schemaIndex = schemaAttributes.findIndex((a) => a.name === userDefinedAttr.name);
            if (schemaIndex > -1) {
                const schemaAttribute = schemaAttributes[schemaIndex];
                if (schemaAttribute) {
                    if (schemaAttribute.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
                        schemaAttribute.mandatory = userDefinedAttr.mandatory;
                    }
                    if (isNotEmptyField(userDefinedAttr.default_values)) {
                        schemaAttribute.defaultValues = (_a = userDefinedAttr.default_values) === null || _a === void 0 ? void 0 : _a.map((v) => ({ id: v, name: v }));
                        // If the default value is a ref with an id, save it to resolve it below.
                        if (schemaAttribute.name !== 'objectMarking' && refsNames.includes(schemaAttribute.name)) {
                            attributesDefaultValuesToResolve[schemaIndex] = (_b = userDefinedAttr.default_values) !== null && _b !== void 0 ? _b : [];
                        }
                    }
                    if (schemaAttribute.scale && isNotEmptyField(userDefinedAttr.scale)) {
                        // override default scale
                        schemaAttribute.scale = JSON.stringify(userDefinedAttr.scale);
                    }
                }
            }
        });
        // Resolve default values ref ids
        const idsToResolve = Object.values(attributesDefaultValuesToResolve).flat();
        const entities = yield internalFindByIdsMapped(context, user, idsToResolve);
        Object.keys(attributesDefaultValuesToResolve).forEach((index) => {
            var _a;
            const defaultValues = (_a = schemaAttributes[Number(index)]) === null || _a === void 0 ? void 0 : _a.defaultValues;
            if (defaultValues) {
                schemaAttributes[Number(index)].defaultValues = defaultValues.map((val) => {
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
    }));
});
export const getMandatoryAttributesForSetting = (context, user, entitySetting) => __awaiter(void 0, void 0, void 0, function* () {
    const attributes = yield getEntitySettingSchemaAttributes(context, user, entitySetting);
    return attributes.filter((a) => a.mandatory).map((a) => a.name);
});
