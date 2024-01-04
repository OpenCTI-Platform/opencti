import * as R from 'ramda';
import { RULE_PREFIX } from './general';
import { UnsupportedError } from '../config/errors';
import type { AttributeDefinition, AttrType } from './attribute-definition';
import { getParentTypes } from './schemaUtils';

export const depsKeysRegister = {
  deps: [] as { src: string, types?: string[] }[],

  add(deps: { src: string, types?: string[] }[]) {
    this.deps = [...this.get(), ...deps];
  },
  get(): { src: string, types?: string[] }[] {
    return this.deps ?? [];
  },
};

let usageProtection = false;
export const schemaAttributesDefinition = {
  // allAttributes is a map of the name and type of all the attributes registered in a schema definition
  // !!! don't use this map !!! It is created for the special context of filter keys checking in case no entity types are given
  allAttributes: new Map<string, string>(),

  // Basic usages
  attributes: {} as Record<string, Map<string, AttributeDefinition>>,
  attributesByTypes: {
    string: new Map<string, void>(),
    date: new Map<string, void>(),
    numeric: new Map<string, void>(),
    boolean: new Map<string, void>(),
    object: new Map<string, void>(),
  } as Record<AttrType, Map<string, void>>,
  upsertByEntity: new Map<string, string[]>(),

  // attributes registration
  registerAttributes(entityType: string, attributes: AttributeDefinition[]) {
    // Check if imported before any business code
    if (usageProtection) {
      throw UnsupportedError('Register attributes use after usage, please check your imports');
    }
    const directAttributes = this.attributes[entityType] ?? new Map<string, AttributeDefinition>();
    // Register given attribute
    const allAttributes = Object.values(this.attributes);
    attributes.forEach((attribute) => {
      // Check the homogeneity of attribute types
      const existingAttribute = allAttributes.find((a) => a.get(attribute.name))?.get(attribute.name); // Maybe better way ?
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
      this.allAttributes.set(attribute.name, attribute.type);
    });
    const parentAttributes = new Map(getParentTypes(entityType)
      .map((type) => Array.from((this.attributes[type] ?? new Map()).values()))
      .flat()
      .map((e) => [e.name, e]));
    const computedWithParentAttributes = new Map([...parentAttributes, ...directAttributes]);
    this.attributes[entityType] = computedWithParentAttributes;
    computedWithParentAttributes.forEach((attr) => {
      // Generate map by types
      this.attributesByTypes[attr.type as AttrType].set(attr.name);
      // Generate map of upsert by entity type
      if (attr.upsert) {
        this.upsertByEntity.set(entityType, [...this.upsertByEntity.get(entityType) ?? [], attr.name]);
      }
    });
  },

  // Usage of raw attributes
  getAllAttributes() {
    usageProtection = true;
    return R.uniqBy((a) => a.name, Object.values(this.attributes).map((a) => Array.from(a.values())).flat());
  },

  // Usage of getAttributes
  getAttributes(entityType: string): Map<string, AttributeDefinition> {
    // const attributesRefs = schemaRelationsRefDefinition.relationsRefMap(entityType) ?? new Map();
    // const attributes = this.attributesCache.get(entityType) ?? new Map();
    // return new Map([...attributesRefs, ...attributes]);
    usageProtection = true;
    return this.attributes[entityType] ?? new Map();
  },
  getAttributeNames(entityType: string): string[] {
    return Array.from(this.getAttributes(entityType).keys());
  },
  getAttribute(entityType: string, name: string): AttributeDefinition | undefined {
    return this.getAttributes(entityType)?.get(name);
  },
  isMultipleAttribute(entityType: string, attributeName: string): boolean {
    return this.getAttribute(entityType, attributeName)?.multiple ?? false;
  },

  // Usage of allAttributes
  getAllAttributesNames(): Array<string> {
    usageProtection = true;
    return Array.from(this.allAttributes.keys());
  },

  // Usage of upsertByEntity
  getUpsertAttributeNames(entityType: string): string[] {
    usageProtection = true;
    return this.upsertByEntity.get(entityType) ?? [];
  },

  // Usage of attributesByTypes
  getAllStringAttributes(excludes: string[] = []) {
    usageProtection = true;
    const strings = Array.from(this.attributesByTypes.string.keys());
    return strings.filter((attr) => !excludes.includes(attr));
  },
  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
    usageProtection = true;
    return attributeType.reduce((r, fn) => this.attributesByTypes[fn].has(attributeName) || r, false);
  },
};

// -- TYPE --
export const isBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'boolean')
);
export const isDateAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date')
);
export const isObjectAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'object')
);
export const isNumericAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'numeric')
);
export const isDateNumericOrBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean')
);

// -- MULTIPLE --

export const isMultipleAttribute = (entityType: string, k: string): boolean => (
  k.startsWith(RULE_PREFIX) || schemaAttributesDefinition.isMultipleAttribute(entityType, k)
);
