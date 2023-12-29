import * as R from 'ramda';
import { RULE_PREFIX } from './general';
import { UnsupportedError } from '../config/errors';
import type { AttributeDefinition, AttrType } from './attribute-definition';
import { getParentTypes } from './schemaUtils';
import { schemaRelationsRefDefinition } from './schema-relationsRef';

export const depsKeysRegister = {
  deps: [] as { src: string, types?: string[] }[],

  add(deps: { src: string, types?: string[] }[]) {
    this.deps = [...this.get(), ...deps];
  },
  get(): { src: string, types?: string[] }[] {
    return this.deps ?? [];
  },
};

export const schemaAttributesDefinition = {
  attributes: {} as Record<string, Map<string, AttributeDefinition>>,
  // allAttributes is a map of the name and type of all the attributes registered in a schema definition
  // !!! don't use this map !!! It is created for the special context of filter keys checking in case no entity types are given
  allAttributes: new Map<string, string>(),
  attributesCache: new Map<string, Map<string, AttributeDefinition>>(),

  attributesByTypes: {
    string: new Map<string, void>(),
    date: new Map<string, void>(),
    numeric: new Map<string, void>(),
    boolean: new Map<string, void>(),
    object: new Map<string, void>(),
  } as Record<AttrType, Map<string, void>>,
  upsertByEntity: new Map<string, string[]>(),

  // attributes
  registerAttributes(entityType: string, attributes: AttributeDefinition[]) {
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
    this.attributes[entityType] = directAttributes;
    this.computeCache(entityType);
  },

  // Extract this method to be call in all methods
  // When an entity not register any relations, the relations for this entity is not computed
  // Call only in register mechanism when all the entities will be migrated
  computeCache(entityType: string) {
    if (this.attributesCache.has(entityType)) return;

    const directAttributes = this.attributes[entityType] ?? [];
    // Register inheritance attributes
    const parentAttributes = new Map(
      getParentTypes(entityType)
        .map((type) => Array.from((this.attributes[type] ?? new Map()).values()))
        .flat()
        .map((e) => [e.name, e])
    );
    const computedWithParentAttributes = new Map([...parentAttributes, ...directAttributes]);
    this.attributesCache.set(entityType, computedWithParentAttributes);

    // Generate cache map
    computedWithParentAttributes.forEach((attr) => {
      // Generate map by types
      this.attributesByTypes[attr.type as AttrType].set(attr.name);
      // Generate map of upsert by entity type
      if (attr.upsert) {
        this.upsertByEntity.set(entityType, [...this.upsertByEntity.get(entityType) ?? [], attr.name]);
      }
    });
  },

  getAllAttributes() {
    return R.uniqBy((a) => a.name, Object.values(this.attributes).map((a) => Array.from(a.values())).flat());
  },

  getRegisteredTypes(): string[] {
    return Array.from(this.attributesCache.keys());
  },

  getAttributes(entityType: string): Map<string, AttributeDefinition> {
    this.computeCache(entityType);
    const attributesRefs = schemaRelationsRefDefinition.relationsRefMap(entityType) ?? new Map();
    const attributes = this.attributesCache.get(entityType) ?? new Map();
    return new Map([...attributesRefs, ...attributes]);
  },

  getAllAttributesNames(): Array<string> {
    return Array.from(this.allAttributes.keys());
  },

  getAttributeNames(entityType: string): string[] {
    this.computeCache(entityType);
    return Array.from(this.getAttributes(entityType).keys());
  },

  getAttribute(entityType: string, name: string): AttributeDefinition | null {
    this.computeCache(entityType);
    const attributeDefinition = this.getAttributes(entityType)?.get(name);
    if (!attributeDefinition) {
      throw UnsupportedError('Cant get definition for attribute', { type: entityType, name });
    }
    return attributeDefinition;
  },

  getUpsertAttributeNames(entityType: string): string[] {
    this.computeCache(entityType);
    return this.upsertByEntity.get(entityType) ?? [];
  },

  isMultipleAttribute(entityType: string, attributeName: string): boolean {
    this.computeCache(entityType);
    return this.getAttribute(entityType, attributeName)?.multiple ?? false;
  },

  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
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
