import * as R from 'ramda';
import { RULE_PREFIX } from './general';
import { UnsupportedError } from '../config/errors';
import { getParentTypes } from './schemaUtils';
export const depsKeysRegister = {
    deps: [],
    add(deps) {
        this.deps = [...this.get(), ...deps];
    },
    get() {
        var _a;
        return (_a = this.deps) !== null && _a !== void 0 ? _a : [];
    },
};
let usageProtection = false;
export const schemaAttributesDefinition = {
    allAttributes: new Map(),
    attributes: {},
    attributesByTypes: {
        string: new Map(),
        date: new Map(),
        numeric: new Map(),
        boolean: new Map(),
        object: new Map(),
    },
    upsertByEntity: new Map(),
    // attributes registration
    registerAttributes(entityType, attributes) {
        var _a;
        // Check if imported before any business code
        if (usageProtection) {
            throw UnsupportedError('Register attributes use after usage, please check your imports');
        }
        const directAttributes = (_a = this.attributes[entityType]) !== null && _a !== void 0 ? _a : new Map();
        // Register given attribute
        const currentAttributes = Object.values(this.attributes);
        attributes.forEach((attribute) => {
            var _a;
            // Check the homogeneity of attribute types
            const existingAttribute = (_a = currentAttributes.find((a) => a.get(attribute.name))) === null || _a === void 0 ? void 0 : _a.get(attribute.name); // Maybe better way ?
            if (existingAttribute) {
                if (existingAttribute.type === 'string') {
                    if (existingAttribute.type !== attribute.type || existingAttribute.format !== attribute.format) {
                        throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
                            existingAttribute,
                            attribute,
                        });
                    }
                }
                if (existingAttribute.type === 'numeric') {
                    if (existingAttribute.type !== attribute.type || existingAttribute.precision !== attribute.precision) {
                        throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
                            existingAttribute,
                            attribute,
                        });
                    }
                }
                if (existingAttribute.type === 'object') {
                    if (existingAttribute.type !== attribute.type || existingAttribute.format !== attribute.format) {
                        throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
                            existingAttribute,
                            attribute,
                        });
                    }
                }
                if (existingAttribute.type === 'date' || existingAttribute.type === 'boolean') {
                    if (existingAttribute.type !== attribute.type) {
                        throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
                            existingAttribute,
                            attribute,
                        });
                    }
                }
            }
            // Check duplicate attributes
            if (directAttributes.has(attribute.name)) {
                throw UnsupportedError('You can\'t register two attributes with the same name on an entity', {
                    attributeName: attribute.name,
                    entityType
                });
            }
            directAttributes.set(attribute.name, attribute);
            // add the attribute name and type in the map of all the attributes
            // to do so, we overwrite an eventual attribute having the same name for an other entity type
            // it's not a problem because if 2 attributes have the same name, they also have the same type
            this.allAttributes.set(attribute.name, attribute);
        });
        const parentAttributes = new Map(getParentTypes(entityType)
            .map((type) => { var _a; return Array.from(((_a = this.attributes[type]) !== null && _a !== void 0 ? _a : new Map()).values()); })
            .flat()
            .map((e) => [e.name, e]));
        const computedWithParentAttributes = new Map([...parentAttributes, ...directAttributes]);
        this.attributes[entityType] = computedWithParentAttributes;
        computedWithParentAttributes.forEach((attr) => {
            var _a;
            // Generate map by types
            this.attributesByTypes[attr.type].set(attr.name);
            // Generate map of upsert by entity type
            if (attr.upsert) {
                this.upsertByEntity.set(entityType, [...(_a = this.upsertByEntity.get(entityType)) !== null && _a !== void 0 ? _a : [], attr.name]);
            }
        });
    },
    selectEntityType(entityType) {
        usageProtection = true;
        if (this.attributes[entityType]) {
            return entityType;
        }
        const types = [...getParentTypes(entityType)].reverse();
        for (let i = 0; i < types.length; i += 1) {
            const type = types[i];
            if (this.attributes[type]) {
                return type;
            }
        }
        throw UnsupportedError('Register relations has no registration for type', { type: entityType });
    },
    // Usage of raw attributes
    getAllAttributes() {
        usageProtection = true;
        return R.uniqBy((a) => a.name, Object.values(this.attributes).map((a) => Array.from(a.values())).flat());
    },
    // Usage of getAttributes
    getAttributes(entityType) {
        var _a;
        // const attributesRefs = schemaRelationsRefDefinition.relationsRefMap(entityType) ?? new Map();
        // const attributes = this.attributesCache.get(entityType) ?? new Map();
        // return new Map([...attributesRefs, ...attributes]);
        return (_a = this.attributes[this.selectEntityType(entityType)]) !== null && _a !== void 0 ? _a : new Map();
    },
    getAttributeNames(entityType) {
        return Array.from(this.getAttributes(entityType).keys());
    },
    getAttribute(entityType, name) {
        var _a;
        return (_a = this.getAttributes(entityType)) === null || _a === void 0 ? void 0 : _a.get(name);
    },
    getAttributeByName(name) {
        return this.allAttributes.get(name);
    },
    isMultipleAttribute(entityType, attributeName) {
        var _a, _b;
        return (_b = (_a = this.getAttribute(entityType, attributeName)) === null || _a === void 0 ? void 0 : _a.multiple) !== null && _b !== void 0 ? _b : false;
    },
    // Usage of allAttributes
    getAllAttributesNames() {
        usageProtection = true;
        return Array.from(this.allAttributes.keys());
    },
    // Usage of upsertByEntity
    getUpsertAttributeNames(entityType) {
        var _a;
        return (_a = this.upsertByEntity.get(this.selectEntityType(entityType))) !== null && _a !== void 0 ? _a : [];
    },
    isSpecificTypeAttribute(attributeName, ...attributeType) {
        usageProtection = true;
        return attributeType.reduce((r, fn) => this.attributesByTypes[fn].has(attributeName) || r, false);
    },
};
// -- TYPE --
export const isBooleanAttribute = (k) => (schemaAttributesDefinition.isSpecificTypeAttribute(k, 'boolean'));
export const isDateAttribute = (k) => (schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date'));
export const isObjectAttribute = (k) => (schemaAttributesDefinition.isSpecificTypeAttribute(k, 'object'));
export const isNumericAttribute = (k) => (schemaAttributesDefinition.isSpecificTypeAttribute(k, 'numeric'));
export const isDateNumericOrBooleanAttribute = (k) => (schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean'));
// -- MULTIPLE --
export const isMultipleAttribute = (entityType, k) => (k.startsWith(RULE_PREFIX) || schemaAttributesDefinition.isMultipleAttribute(entityType, k));
