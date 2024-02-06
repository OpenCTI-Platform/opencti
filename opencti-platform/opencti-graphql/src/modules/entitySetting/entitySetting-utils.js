var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { head } from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_AUTHORIZED_MEMBERS, INPUT_MARKINGS } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, isStixDomainObject } from '../../schema/stixDomainObject';
import { UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { MEMBER_ACCESS_CREATOR, SYSTEM_USER } from '../../utils/access';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../task/task-types';
import { isNumericAttribute, schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isEmptyField } from '../../database/utils';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
export const defaultEntitySetting = {
    platform_entity_files_ref: false,
    platform_hidden_type: false,
    enforce_reference: false,
    attributes_configuration: JSON.stringify([]),
    workflow_configuration: true,
};
export const defaultScale = JSON.stringify({
    local_config: {
        better_side: 'min',
        min: {
            value: 0,
            color: '#f44336',
            label: '6 - Truth Cannot be judged',
        },
        max: {
            value: 100,
            color: '#6e44ad',
            label: 'Out of Range',
        },
        ticks: [
            { value: 1, color: '#f57423', label: '5 - Improbable' },
            { value: 20, color: '#ff9800', label: '4 - Doubtful' },
            { value: 40, color: '#f8e71c', label: '3 - Possibly True' },
            { value: 60, color: '#92f81c', label: '2 - Probably True' },
            { value: 80, color: '#4caf50', label: '1 - Confirmed by other sources' },
        ],
    }
});
// Available settings works by override.
export const availableSettings = {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference', 'workflow_configuration'],
    [ABSTRACT_STIX_CORE_RELATIONSHIP]: ['attributes_configuration', 'enforce_reference', 'workflow_configuration'],
    [STIX_SIGHTING_RELATIONSHIP]: ['attributes_configuration', 'enforce_reference', 'platform_hidden_type', 'workflow_configuration'],
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: ['platform_hidden_type'],
    // enforce_reference not available on specific entities
    [ENTITY_TYPE_CONTAINER_NOTE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
    [ENTITY_TYPE_CONTAINER_OPINION]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
    [ENTITY_TYPE_CONTAINER_CASE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
    [ENTITY_TYPE_CONTAINER_TASK]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
};
export const getAvailableSettings = (targetType) => {
    var _a, _b;
    let settings;
    if (isStixDomainObject(targetType)) {
        settings = (_a = availableSettings[targetType]) !== null && _a !== void 0 ? _a : availableSettings[ABSTRACT_STIX_DOMAIN_OBJECT];
    }
    else if (isStixCyberObservable(targetType)) {
        settings = (_b = availableSettings[targetType]) !== null && _b !== void 0 ? _b : availableSettings[ABSTRACT_STIX_CYBER_OBSERVABLE];
    }
    else {
        settings = availableSettings[targetType];
    }
    if (!settings) {
        throw UnsupportedError('This entity type is not support for entity settings', { target_type: targetType });
    }
    return settings;
};
// -- HELPERS --
export const getEntitySettingFromCache = (context, type) => __awaiter(void 0, void 0, void 0, function* () {
    const entitySettings = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
    let entitySetting = entitySettings.find((es) => es.target_type === type);
    if (!entitySetting) {
        // Inheritance
        if (isStixCoreRelationship(type)) {
            entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP);
        }
        else if (isStixCyberObservable(type)) {
            entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CYBER_OBSERVABLE);
        }
    }
    return entitySetting;
});
export const getAttributesConfiguration = (entitySetting) => {
    if (entitySetting === null || entitySetting === void 0 ? void 0 : entitySetting.attributes_configuration) {
        return JSON.parse(entitySetting.attributes_configuration);
    }
    return null;
};
export const getDefaultValues = (attributeConfiguration, multiple) => {
    if (attributeConfiguration.default_values) {
        if (multiple) {
            return attributeConfiguration.default_values;
        }
        return head(attributeConfiguration.default_values);
    }
    return undefined;
};
export const fillDefaultValues = (user, input, entitySetting) => {
    const attributesConfiguration = getAttributesConfiguration(entitySetting);
    if (!attributesConfiguration) {
        return input;
    }
    const filledValues = new Map();
    attributesConfiguration.filter((attr) => attr.default_values)
        .forEach((attr) => {
        var _a, _b, _c;
        // Do not compute default value if we already have a value in the input.
        // Empty is a valid value (i.e. [] for arrays or "" for strings).
        if (input[attr.name] === undefined || input[attr.name] === null) {
            const attributeDef = schemaAttributesDefinition.getAttribute(entitySetting.target_type, attr.name);
            const refDef = schemaRelationsRefDefinition.getRelationRef(entitySetting.target_type, attr.name);
            let isMultiple = false;
            if (attributeDef) {
                isMultiple = attributeDef.multiple;
            }
            else if (refDef) {
                isMultiple = refDef.multiple;
            }
            const defaultValue = getDefaultValues(attr, isMultiple);
            const isNumeric = isNumericAttribute(attr.name);
            const parsedValue = isNumeric ? Number(defaultValue) : defaultValue;
            if (attr.name === INPUT_AUTHORIZED_MEMBERS && parsedValue) {
                const defaultAuthorizedMembers = parsedValue.map((v) => JSON.parse(v));
                // Replace dynamic creator rule with the id of the user making the query.
                const creatorRule = defaultAuthorizedMembers.find((v) => v.id === MEMBER_ACCESS_CREATOR);
                if (creatorRule) {
                    creatorRule.id = user.id;
                }
                filledValues.set(attr.name, defaultAuthorizedMembers);
            }
            else if (attr.name === INPUT_MARKINGS && parsedValue) {
                const defaultMarkings = (_a = user === null || user === void 0 ? void 0 : user.default_marking) !== null && _a !== void 0 ? _a : [];
                const globalDefaultMarking = ((_c = (_b = defaultMarkings.find((entry) => entry.entity_type === 'GLOBAL')) === null || _b === void 0 ? void 0 : _b.values) !== null && _c !== void 0 ? _c : []).map((m) => m.id);
                if (!isEmptyField(globalDefaultMarking)) {
                    filledValues.set(INPUT_MARKINGS, globalDefaultMarking);
                }
            }
            else {
                filledValues.set(attr.name, parsedValue);
            }
        }
    });
    return Object.assign(Object.assign({}, input), Object.fromEntries(filledValues));
};
